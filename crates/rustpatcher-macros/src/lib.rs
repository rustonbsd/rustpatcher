use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, ItemFn};

#[proc_macro_attribute]
pub fn main(_args: TokenStream, input: TokenStream) -> TokenStream {
    let input_fn = parse_macro_input!(input as ItemFn);
    let version = env!("CARGO_PKG_VERSION");
    
    let expanded = quote! {
        // Create a static initializer that runs before main
        #[ctor::ctor]
        fn __init_version() {
            rustpatcher::__set_version(#version);
        }

        #input_fn
    };

    TokenStream::from(expanded)
}