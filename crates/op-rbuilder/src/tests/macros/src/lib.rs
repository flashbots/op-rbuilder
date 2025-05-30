use proc_macro::TokenStream;
use quote::{quote, ToTokens};
use syn::{parse_macro_input, punctuated::Punctuated, Expr, ItemFn, Meta, Token};

struct TestConfig {
    standard: Option<Option<Expr>>, // None = not specified, Some(None) = default, Some(Some(expr)) = custom
    flashblocks: Option<Option<Expr>>, // Same as above
    args: Option<Expr>,             // Expression to pass to LocalInstance::new()
}

impl syn::parse::Parse for TestConfig {
    fn parse(input: syn::parse::ParseStream) -> syn::Result<Self> {
        let mut config = TestConfig {
            standard: None,
            flashblocks: None,
            args: None,
        };

        if input.is_empty() {
            // No arguments provided, generate both with defaults
            config.standard = Some(None);
            config.flashblocks = Some(None);
            return Ok(config);
        }

        let args: Punctuated<Meta, Token![,]> = input.parse_terminated(Meta::parse, Token![,])?;

        for arg in args {
            match arg {
                Meta::Path(path) if path.is_ident("standard") => {
                    config.standard = Some(None);
                }
                Meta::Path(path) if path.is_ident("flashblocks") => {
                    config.flashblocks = Some(None);
                }
                Meta::NameValue(nv) if nv.path.is_ident("standard") => {
                    config.standard = Some(Some(nv.value));
                }
                Meta::NameValue(nv) if nv.path.is_ident("flashblocks") => {
                    config.flashblocks = Some(Some(nv.value));
                }
                Meta::NameValue(nv) if nv.path.is_ident("args") => {
                    config.args = Some(nv.value);
                }
                _ => {
                    return Err(syn::Error::new_spanned(
                        arg,
                        "Unknown attribute. Use 'standard', 'flashblocks', or 'args'",
                    ));
                }
            }
        }

        // Validate that custom expressions and args are not used together
        if let Some(Some(_)) = &config.standard {
            if config.args.is_some() {
                return Err(syn::Error::new_spanned(
                    config.args.as_ref().unwrap(),
                    "Cannot use 'args' with custom 'standard' expression. Use either 'standard = expression' or 'args = expression', not both.",
                ));
            }
        }

        if let Some(Some(_)) = &config.flashblocks {
            if config.args.is_some() {
                return Err(syn::Error::new_spanned(
                    config.args.as_ref().unwrap(),
                    "Cannot use 'args' with custom 'flashblocks' expression. Use either 'flashblocks = expression' or 'args = expression', not both.",
                ));
            }
        }

        // If only args is specified, generate both standard and flashblocks tests
        if config.standard.is_none() && config.flashblocks.is_none() && config.args.is_some() {
            config.standard = Some(None);
            config.flashblocks = Some(None);
        }

        Ok(config)
    }
}

#[proc_macro_attribute]
pub fn rb_test(args: TokenStream, input: TokenStream) -> TokenStream {
    let input_fn = parse_macro_input!(input as ItemFn);
    let config = parse_macro_input!(args as TestConfig);

    validate_signature(&input_fn);

    // Create the original function without test attributes (helper function)
    let mut helper_fn = input_fn.clone();
    // Remove any existing test attributes
    helper_fn
        .attrs
        .retain(|attr| !attr.path().is_ident("test") && !attr.path().is_ident("tokio"));

    let original_name = &input_fn.sig.ident;

    let mut generated_functions = vec![quote! { #helper_fn }];

    // Generate standard test if requested
    if let Some(standard_init) = config.standard {
        let standard_test_name =
            syn::Ident::new(&format!("{}_standard", original_name), original_name.span());

        let instance_init = match (standard_init, &config.args) {
            (None, None) => quote! { crate::tests::LocalInstance::standard().await? },
            (None, Some(args_expr)) => {
                quote! { crate::tests::LocalInstance::new::<crate::builders::StandardBuilder>(#args_expr).await? }
            }
            (Some(expr), _) => quote! { #expr },
        };

        generated_functions.push(quote! {
            #[tokio::test]
            async fn #standard_test_name() -> eyre::Result<()> {
                let instance = #instance_init;
                #original_name(instance).await
            }
        });
    }

    // Generate flashblocks test if requested
    if let Some(flashblocks_init) = config.flashblocks {
        let flashblocks_test_name = syn::Ident::new(
            &format!("{}_flashblocks", original_name),
            original_name.span(),
        );

        let instance_init = match (flashblocks_init, &config.args) {
            (None, None) => quote! { crate::tests::LocalInstance::flashblocks().await? },
            (None, Some(args_expr)) => {
                quote! { crate::tests::LocalInstance::new::<crate::builders::FlashblocksBuilder>(#args_expr).await? }
            }
            (Some(expr), _) => quote! { #expr },
        };

        generated_functions.push(quote! {
            #[tokio::test]
            async fn #flashblocks_test_name() -> eyre::Result<()> {
                let instance = #instance_init;
                #original_name(instance).await
            }
        });
    }

    TokenStream::from(quote! {
        #(#generated_functions)*
    })
}

fn validate_signature(item_fn: &ItemFn) {
    if item_fn.sig.asyncness.is_none() {
        panic!("Function must be async.");
    }
    if item_fn.sig.inputs.len() != 1 {
        panic!("Function must have exactly one parameter of type LocalInstance.");
    }

    let output_types = item_fn
        .sig
        .output
        .to_token_stream()
        .to_string()
        .replace(" ", "");

    if output_types != "->eyre::Result<()>" {
        panic!(
            "Function must return Result<(), eyre::Error>. Actual: {}",
            output_types
        );
    }
}
