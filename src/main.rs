use crate::definition::Definition;

mod bindings {
    windows::include_bindings!();
}

mod authenticode;
mod definition;
mod error;
mod version;

fn main() {
    let def = Definition::new(r#"C:\Users\Josh\Downloads\mpam-feX64.exe"#);
    let info = def.authenticode_data().unwrap();
    let ver = def.version().unwrap();

    dbg!(info.read_subject_cert());
    dbg!(info.read_issuer_cert());
    dbg!(ver);
}
