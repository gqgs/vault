extern crate argon2;
extern crate crypto as cryptolib;
extern crate gdk_pixbuf;
extern crate gio;
extern crate glib;
extern crate gtk;
extern crate rand;

use gio::prelude::*;
use std::env::args;

mod config;
mod crypto;
mod editor;
mod state;
mod string;

fn main() {
    let application = gtk::Application::new(Some(config::ID), Default::default())
        .expect("Failed to initialize GTK.");

    application.connect_activate(|app| {
        editor::Editor::new().run(app);
    });

    application.run(&args().collect::<Vec<_>>());
}
