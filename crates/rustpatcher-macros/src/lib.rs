use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, ItemFn, LitStr};

#[proc_macro_attribute]
pub fn public_key(args: TokenStream, input: TokenStream) -> TokenStream {

    let input_fn = parse_macro_input!(input as ItemFn);
    let public_key_lit = parse_macro_input!(args as LitStr);

    let expanded = quote! {
        #[::ctor::ctor]
        fn __rustpatcher2_init_version() {
            ::rustpatcher2::embed::embed(env!("CARGO_PKG_VERSION"), #public_key_lit);
        }

        #input_fn
    };

    TokenStream::from(expanded)
}