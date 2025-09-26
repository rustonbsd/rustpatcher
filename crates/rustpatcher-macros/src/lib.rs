use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, ItemFn, Expr};

#[proc_macro_attribute]
pub fn public_key(args: TokenStream, input: TokenStream) -> TokenStream {
    let input_fn = parse_macro_input!(input as ItemFn);
    let public_key_expr = parse_macro_input!(args as Expr);

    let expanded = quote! {
        const _: () = {
            #[::ctor::ctor]
            fn __rustpatcher_init_version() {
                let __rustpatcher_public_key: &'static str = {
                    let __cow: ::std::borrow::Cow<'static, str> =
                        ::std::convert::Into::<::std::borrow::Cow<'static, str>>::into(#public_key_expr);
                    match __cow {
                        ::std::borrow::Cow::Borrowed(s) => s,
                        ::std::borrow::Cow::Owned(s) => ::std::boxed::Box::leak(s.into_boxed_str()),
                    }
                };
                ::rustpatcher::embed::embed(env!("CARGO_PKG_VERSION"), __rustpatcher_public_key);
            }
        };

        #input_fn
    };

    TokenStream::from(expanded)
}