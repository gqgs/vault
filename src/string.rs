pub trait StaticStr {
    fn as_static_str(&self) -> &'static str;
}
