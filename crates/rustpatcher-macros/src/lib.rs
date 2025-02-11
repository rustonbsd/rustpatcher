use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, ItemFn};

#[proc_macro_attribute]
pub fn main(_args: TokenStream, input: TokenStream) -> TokenStream {
    let input_fn = parse_macro_input!(input as ItemFn);
    let expanded = quote! {
        // Create a static initializer that runs before main
        #[ctor::ctor]
        fn __init_version() {
            rustpatcher::version_embed::__set_version(env!("CARGO_PKG_VERSION"));
        }

        #input_fn
    };

    TokenStream::from(expanded)
}