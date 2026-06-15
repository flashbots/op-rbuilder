use proc_macro::TokenStream;
use quote::{ToTokens, quote};
use syn::{Expr, ItemFn, Meta, Token, parse_macro_input, punctuated::Punctuated};

struct TestConfig {
    args: Option<Expr>,       // Expression to pass to LocalInstance::new()
    config: Option<Expr>,     // NodeConfig<OpChainSpec> for new_with_config
    test_hooks: Option<Expr>, // ContinuousTestHooks injected into the builder config
    multi_threaded: bool,     // Whether to use multi_thread flavor
}

impl syn::parse::Parse for TestConfig {
    fn parse(input: syn::parse::ParseStream) -> syn::Result<Self> {
        let mut config = TestConfig {
            args: None,
            config: None,
            test_hooks: None,
            multi_threaded: false,
        };

        if input.is_empty() {
            return Ok(config);
        }

        let args: Punctuated<Meta, Token![,]> = input.parse_terminated(Meta::parse, Token![,])?;

        for arg in args {
            match arg {
                Meta::Path(path) => {
                    if let Some(ident) = path.get_ident() {
                        let name = ident.to_string();
                        if name == "multi_threaded" {
                            config.multi_threaded = true;
                        } else {
                            return Err(syn::Error::new_spanned(
                                path,
                                format!(
                                    "Unknown attribute '{}'. Use 'multi_threaded', 'args', 'config', or 'test_hooks'",
                                    name
                                ),
                            ));
                        }
                    }
                }
                Meta::NameValue(nv) => {
                    if let Some(ident) = nv.path.get_ident() {
                        let name = ident.to_string();
                        if name == "args" {
                            config.args = Some(nv.value);
                        } else if name == "config" {
                            config.config = Some(nv.value);
                        } else if name == "test_hooks" {
                            config.test_hooks = Some(nv.value);
                        } else {
                            return Err(syn::Error::new_spanned(
                                nv.path,
                                format!(
                                    "Unknown attribute '{}'. Use 'multi_threaded', 'args', 'config', or 'test_hooks'",
                                    name
                                ),
                            ));
                        }
                    }
                }
                _ => {
                    return Err(syn::Error::new_spanned(
                        arg,
                        "Invalid attribute format. Use 'multi_threaded', 'args', 'config', or 'test_hooks'",
                    ));
                }
            }
        }

        Ok(config)
    }
}

fn generate_instance_init(
    args: &Option<Expr>,
    config: &Option<Expr>,
    test_hooks: &Option<Expr>,
) -> proc_macro2::TokenStream {
    let args_init = match args {
        None => quote! {
            {
                let mut args = crate::args::OpRbuilderArgs::default();
                args.flashblocks.flashblocks_port = crate::tests::get_available_port();
                args.flashblocks.flashblocks_end_buffer_ms = 75;
                args
            }
        },
        Some(args_expr) => quote! {
            {
                let mut args = #args_expr;
                args.flashblocks.flashblocks_port = crate::tests::get_available_port();
                args.flashblocks.flashblocks_end_buffer_ms = 75;
                args
            }
        },
    };

    match (config, test_hooks) {
        (None, None) => {
            quote! { crate::tests::LocalInstance::new(#args_init).await? }
        }
        (Some(config_expr), None) => {
            quote! {
                crate::tests::LocalInstance::new_with_config(#args_init, #config_expr).await?
            }
        }
        (None, Some(hooks_expr)) => {
            quote! {
                crate::tests::LocalInstance::new_with_test_hooks(#args_init, #hooks_expr).await?
            }
        }
        (Some(config_expr), Some(hooks_expr)) => {
            quote! {
                crate::tests::LocalInstance::new_with_config_and_hooks(
                    #args_init, #config_expr, #hooks_expr
                ).await?
            }
        }
    }
}

#[proc_macro_attribute]
pub fn rb_test(args: TokenStream, input: TokenStream) -> TokenStream {
    let input_fn = parse_macro_input!(input as ItemFn);
    let config = parse_macro_input!(args as TestConfig);

    validate_signature(&input_fn);

    let test_name = &input_fn.sig.ident;
    let instance_init = generate_instance_init(&config.args, &config.config, &config.test_hooks);

    let test_attribute = if config.multi_threaded {
        quote! { #[tokio::test(flavor = "multi_thread")] }
    } else {
        quote! { #[tokio::test] }
    };

    // Extract the parameter name from the function signature
    let param_name = if let syn::FnArg::Typed(pat_type) = &input_fn.sig.inputs[0] {
        &pat_type.pat
    } else {
        panic!("Expected typed parameter");
    };

    // Get the function body
    let body = &input_fn.block;

    TokenStream::from(quote! {
        #test_attribute
        async fn #test_name() -> eyre::Result<()> {
            let subscriber = tracing_subscriber::fmt()
                .with_env_filter(std::env::var("RUST_LOG")
                    .unwrap_or_else(|_| "info".to_string()))
                .with_file(true)
                .with_line_number(true)
                .with_test_writer()
                .finish();
            let _guard = tracing::subscriber::set_global_default(subscriber);
            tracing::info!("{} start", stringify!(#test_name));

            let #param_name = #instance_init;

            // Inline the test body
            #body
        }
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
        panic!("Function must return Result<(), eyre::Error>. Actual: {output_types}",);
    }
}
