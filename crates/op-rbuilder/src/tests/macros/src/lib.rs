use proc_macro::TokenStream;
use quote::{ToTokens, quote};
use syn::{Expr, ItemFn, Meta, Token, parse_macro_input, punctuated::Punctuated};

struct TestConfig {
    standard: Option<Option<Expr>>, // None = not specified, Some(None) = default, Some(Some(expr)) = custom
    flashblocks: Option<Option<Expr>>, // Same as above
    args: Option<Expr>,             // Expression to pass to LocalInstance::new()
    config: Option<Expr>,           // NodeConfig<OpChainSpec> for new_with_config
}

impl syn::parse::Parse for TestConfig {
    fn parse(input: syn::parse::ParseStream) -> syn::Result<Self> {
        let mut config = TestConfig {
            standard: None,
            flashblocks: None,
            args: None,
            config: None,
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
                Meta::NameValue(nv) if nv.path.is_ident("config") => {
                    config.config = Some(nv.value);
                }
                _ => {
                    return Err(syn::Error::new_spanned(
                        arg,
                        "Unknown attribute. Use 'standard', 'flashblocks', 'args', or 'config'",
                    ));
                }
            }
        }

        // Validate that custom expressions and args/config are not used together
        if let Some(Some(_)) = &config.standard {
            if config.args.is_some() || config.config.is_some() {
                return Err(syn::Error::new_spanned(
                    config.args.as_ref().or(config.config.as_ref()).unwrap(),
                    "Cannot use 'args' or 'config' with custom 'standard' expression. Use either 'standard = expression' or 'args/config' parameters, not both.",
                ));
            }
        }

        if let Some(Some(_)) = &config.flashblocks {
            if config.args.is_some() || config.config.is_some() {
                return Err(syn::Error::new_spanned(
                    config.args.as_ref().or(config.config.as_ref()).unwrap(),
                    "Cannot use 'args' or 'config' with custom 'flashblocks' expression. Use either 'flashblocks = expression' or 'args/config' parameters, not both.",
                ));
            }
        }

        // If only args/config is specified, generate both standard and flashblocks tests
        if config.standard.is_none()
            && config.flashblocks.is_none()
            && (config.args.is_some() || config.config.is_some())
        {
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

        let instance_init = match (standard_init, &config.args, &config.config) {
            (None, None, None) => quote! { crate::tests::LocalInstance::standard().await? },
            (None, Some(args_expr), None) => {
                quote! { crate::tests::LocalInstance::new::<crate::builders::StandardBuilder>(#args_expr).await? }
            }
            (None, None, Some(config_expr)) => {
                quote! { crate::tests::LocalInstance::new_with_config::<crate::builders::StandardBuilder>(Default::default(), #config_expr).await? }
            }
            (None, Some(args_expr), Some(config_expr)) => {
                quote! { crate::tests::LocalInstance::new_with_config::<crate::builders::StandardBuilder>(#args_expr, #config_expr).await? }
            }
            (Some(expr), _, _) => quote! { #expr },
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

        let instance_init = match (flashblocks_init, &config.args, &config.config) {
            (None, None, None) => quote! { crate::tests::LocalInstance::flashblocks().await? },
            (None, Some(args_expr), None) => {
                // Use custom flashblocks args with enabled=true and flashblocks_port=0
                quote! {
                    crate::tests::LocalInstance::new::<crate::builders::FlashblocksBuilder>({
                        let mut args = #args_expr;
                        args.flashblocks.enabled = true;
                        args.flashblocks.flashblocks_port = 0;
                        args
                    }).await?
                }
            }
            (None, None, Some(config_expr)) => {
                quote! {
                    crate::tests::LocalInstance::new_with_config::<crate::builders::FlashblocksBuilder>({
                        let mut args = crate::args::OpRbuilderArgs::default();
                        args.flashblocks.enabled = true;
                        args.flashblocks.flashblocks_port = 0;
                        args
                    }, #config_expr).await?
                }
            }
            (None, Some(args_expr), Some(config_expr)) => {
                quote! {
                    crate::tests::LocalInstance::new_with_config::<crate::builders::FlashblocksBuilder>({
                        let mut args = #args_expr;
                        args.flashblocks.enabled = true;
                        args.flashblocks.flashblocks_port = 0;
                        args
                    }, #config_expr).await?
                }
            }
            (Some(expr), _, _) => quote! { #expr },
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
// in cargo tests threads are named after the test function that
// is running, so we can check if the current thread is a flashblocks test
#[proc_macro]
pub fn if_flashblocks(input: TokenStream) -> TokenStream {
    let input = proc_macro2::TokenStream::from(input);

    TokenStream::from(quote! {
        if std::thread::current().name().unwrap_or("").ends_with("_flashblocks") {
            #input
        }
    })
}
