use proc_macro::TokenStream;
use syn::{parse_macro_input, ItemFn};
use quote::quote;

#[proc_macro_attribute]
pub fn patcher(_args: TokenStream, input: TokenStream) -> TokenStream {
    let input_fn = parse_macro_input!(input as ItemFn);
    let version = env!("CARGO_PKG_VERSION");
    
    let expanded = quote! {
        #[used]
        #[allow(non_upper_case_globals)]
        #[link_section = ".init_array"]
        static __version_init: fn() = {
            fn init() {
                let _ = rustpatcher::version_embed::APP_VERSION.set(#version);
            }
            init
        };

        #input_fn
    };

    TokenStream::from(expanded)
}