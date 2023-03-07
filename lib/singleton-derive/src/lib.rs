use darling::FromDeriveInput;
use proc_macro::{self, TokenStream};
use quote::quote;
use syn::{parse_macro_input, DeriveInput};

#[derive(FromDeriveInput)]
#[darling(default, attributes(singleton))]
struct Opts {
    sync: bool,
    use_once_cell: bool,
    use_mutex: bool,
    use_async_trait: bool,
    use_singleton_guard: bool,
    use_singleton: bool,
}

impl Default for Opts {
    fn default() -> Self {
        Self {
            sync: true,
            use_once_cell: true,
            use_mutex: true,
            use_async_trait: true,
            use_singleton_guard: true,
            use_singleton: true,
        }
    }
}

#[proc_macro_derive(Singleton, attributes(singleton))]
pub fn derive(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input);
    let opts = Opts::from_derive_input(&input).expect("Wrong options");
    let DeriveInput { ident, .. } = input;

    let uses = if opts.use_once_cell {
        quote! {
            use singleton::OnceCell;
        }
    } else {
        quote! {}
    };

    let uses = if opts.use_mutex {
        quote! {
            #uses
            use singleton::Mutex;
        }
    } else {
        quote! {
            #uses
        }
    };

    let uses = if opts.use_async_trait {
        quote! {
            #uses
            use singleton::async_trait;
        }
    } else {
        quote! {
            #uses
        }
    };

    let uses = if opts.use_singleton_guard {
        if opts.sync {
            quote! {
                #uses
                use singleton::sync::SingletonGuard;
            }
        } else {
            quote! {
                #uses
            }
        }
    } else {
        quote! {
            #uses
        }
    };

    let uses = if opts.use_singleton {
        if opts.sync {
            quote! {
                #uses
                use singleton::sync::Singleton;
            }
        } else {
            quote! {
                #uses
                use singleton::unsync::Singleton;
            }
        }
    } else {
        quote! {
            #uses
        }
    };

    let output = if opts.sync {
        quote! {
            #uses

            #[async_trait]
            impl Singleton<#ident> for #ident {
                fn get() -> &'static Mutex<#ident> {
                    static INSTANCE: OnceCell<Mutex<#ident>> = OnceCell::new();
                    INSTANCE.get_or_init(|| Mutex::new(#ident::init()))
                }

                async fn lock<'a>() -> SingletonGuard<'a, #ident> {
                    SingletonGuard {
                        inner: #ident::get().lock().await,
                    }
                }
            }
        }
    } else {
        quote! {
            #uses

            impl Singleton<#ident> for #ident {
                fn get() -> &'static #ident {
                    static INSTANCE: OnceCell<#ident> = OnceCell::new();
                    INSTANCE.get_or_init(|| #ident::init())
                }
            }
        }
    };

    output.into()
}
