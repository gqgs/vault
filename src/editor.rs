use gdk_pixbuf::Pixbuf;
use glib::{Receiver, Sender};
use gtk::prelude::*;
use gtk::{
    Adjustment, ButtonsType, DialogFlags, Entry, EntryBuffer, FileChooserAction, FileChooserDialog,
    Label, Menu, MenuBar, MenuItem, MessageDialog, MessageType, PolicyType, ResponseType,
    ScrolledWindow, TextBuffer, TextTagTable, TextView, WindowPosition, WrapMode,
};
use std::cell::RefCell;
use std::fs;
use std::fs::File;
use std::io::prelude::*;
use std::rc::Rc;

use state::cipher::Cipher;
use state::cost::Cost;
use state::hash::Hash;
use state::kdf::KDF;

use config;
use state;
use string;

macro_rules! clear_buffer {
    ($buffer:ident) => {{
        let (mut start, mut end) = $buffer.get_bounds();
        $buffer.delete(&mut start, &mut end);
    }};
}

macro_rules! close_handler {
    ($window:ident) => (
        let flags = DialogFlags::empty();
        let dialog = MessageDialog::new(Some(&$window), flags, MessageType::Question, ButtonsType::YesNo, "Are you sure you want to exit?");
        dialog.connect_response(glib::clone!(@strong $window => move |_, resp| {
            if resp == ResponseType::Yes.into() {
                unsafe { $window.destroy() };
            }
        }));
        dialog.run();
        dialog.close();
    )
}

pub enum Action {
    // update text
    UpdateTextView(String),
}

pub struct Editor {
    label: Label,
    state: Rc<RefCell<state::State>>,
    sender: Sender<state::Action>,
    receiver: RefCell<Option<Receiver<state::Action>>>,
}

impl Editor {
    pub fn new() -> Editor {
        let (sender, r) = glib::MainContext::channel(glib::PRIORITY_DEFAULT);
        let state = state::State::new();
        Editor {
            sender,
            label: Label::new(Some(&state.to_string())),
            state: Rc::new(RefCell::new(state)),
            receiver: RefCell::new(Some(r)),
        }
    }

    fn new_menu_item(&self, label_text: impl string::StaticStr + state::Updater) -> MenuItem {
        let menu_item = MenuItem::with_label(label_text.as_static_str());
        let label_clone = self.label.clone();
        let state = Rc::clone(&self.state);
        let updatemsg = label_text.update();
        menu_item.connect_activate(move |_| {
            state.borrow_mut().update(updatemsg);
            label_clone.set_label(&state.borrow().to_string());
        });
        menu_item
    }

    pub fn run(&self, application: &gtk::Application) {
        let icon = Pixbuf::from_file(config::ICON).unwrap();
        let window = gtk::ApplicationWindow::new(application);
        window.set_title(config::TITLE);
        window.set_position(WindowPosition::Center);
        window.set_size_request(800, 500);
        window.set_icon(Some(&icon));
        window.set_resizable(false);
        window.connect_delete_event(glib::clone!(@strong window => move |_, _| {
            close_handler!(window);
            Inhibit(true)
        }));

        let v_box = gtk::Box::new(gtk::Orientation::Vertical, 10);
        let menu = MenuBar::new();
        let filemenu = Menu::new();
        let file = MenuItem::with_label("File");
        let new_file = MenuItem::with_label("New File");
        let open_file = MenuItem::with_label("Open...");
        let save_file_as = MenuItem::with_label("Save as..");
        let close = MenuItem::with_label("Close");
        filemenu.append(&new_file);
        filemenu.append(&open_file);
        filemenu.append(&save_file_as);
        filemenu.append(&close);
        file.set_submenu(Some(&filemenu));
        menu.append(&file);

        let ciphermenu = Menu::new();
        let cipher = MenuItem::with_label("Cipher");
        ciphermenu.append(&self.new_menu_item(Cipher::AESCBC));
        ciphermenu.append(&self.new_menu_item(Cipher::CHACHA20));
        ciphermenu.append(&self.new_menu_item(Cipher::SALSA20));
        cipher.set_submenu(Some(&ciphermenu));
        menu.append(&cipher);

        let costmenu = Menu::new();
        let cost = MenuItem::with_label("Cost");
        costmenu.append(&self.new_menu_item(Cost::LOW));
        costmenu.append(&self.new_menu_item(Cost::MEDIUM));
        costmenu.append(&self.new_menu_item(Cost::HIGH));
        cost.set_submenu(Some(&costmenu));
        menu.append(&cost);

        let hashmenu = Menu::new();
        let hash = MenuItem::with_label("Hash");
        let blake = MenuItem::with_label("BLAKE");
        let blakemenu = Menu::new();
        blakemenu.append(&self.new_menu_item(Hash::BLAKE2B));
        blakemenu.append(&self.new_menu_item(Hash::BLAKE2S));
        blake.set_submenu(Some(&blakemenu));
        hashmenu.append(&blake);

        let sha2 = MenuItem::with_label("SHA2");
        let sha2menu = Menu::new();
        sha2menu.append(&self.new_menu_item(Hash::SHA2_256));
        sha2menu.append(&self.new_menu_item(Hash::SHA2_384));
        sha2menu.append(&self.new_menu_item(Hash::SHA2_512));
        sha2.set_submenu(Some(&sha2menu));
        hashmenu.append(&sha2);

        let sha3 = MenuItem::with_label("SHA3");
        let sha3menu = Menu::new();
        sha3menu.append(&self.new_menu_item(Hash::SHA3_256));
        sha3menu.append(&self.new_menu_item(Hash::SHA3_384));
        sha3menu.append(&self.new_menu_item(Hash::SHA3_512));
        sha3.set_submenu(Some(&sha3menu));
        hashmenu.append(&sha3);

        hashmenu.append(&self.new_menu_item(Hash::RIPEMD160));

        hash.set_submenu(Some(&hashmenu));
        menu.append(&hash);

        let kdfmenu = Menu::new();
        let kdf = MenuItem::with_label("KDF");
        kdfmenu.append(&self.new_menu_item(KDF::PBKDF2));
        kdfmenu.append(&self.new_menu_item(KDF::ARGON2));
        kdf.set_submenu(Some(&kdfmenu));
        menu.append(&kdf);

        let text_buffer = TextBuffer::new(None::<&TextTagTable>);
        let text_view = TextView::with_buffer(&text_buffer);
        text_view.set_wrap_mode(WrapMode::WordChar);
        text_view.set_left_margin(8);

        let receiver = self
            .receiver
            .borrow_mut()
            .take()
            .expect("failed to create receiver");
        let state = self.state.clone();
        receiver.attach(
            None,
            glib::clone!(@strong text_buffer => move |action| {
                match state.borrow().action(action) {
                    Some(Action::UpdateTextView(text)) => {
                        clear_buffer!(text_buffer);
                        text_buffer.set_text(text.as_str());
                    },
                    None => {},
                }
                glib::Continue(true)
            }),
        );

        new_file.connect_activate(glib::clone!(@weak text_buffer => move |_| {
            clear_buffer!(text_buffer);
        }));

        open_file.connect_activate(glib::clone!(@strong window, @strong self.sender as sender => move |_| {
            let dialog = FileChooserDialog::new(Some("Opening file..."), Some(&window), FileChooserAction::Open);
            dialog.set_select_multiple(false);
            dialog.add_button("Open", ResponseType::Ok.into());
            dialog.add_button("Cancel", ResponseType::Cancel.into());
            dialog.connect_response(glib::clone!(@strong window, @strong sender => move |dialog, resp| {
                if resp == ResponseType::Ok.into() {
                    if let Some(path) = dialog.get_filename() {
                        let display = path.display();
                        let mut file = match File::open(&path) {
                            Err(err) => panic!("Error opening file {}: {}", display, err),
                            Ok(file) => file,
                        };

                        let metadata = fs::metadata(&path).unwrap();
                        if metadata.is_dir() {
                            dialog.set_current_folder(&path);
                        } else {
                            dialog.close();
                            let mut content = Vec::<u8>::new();
                            match file.read_to_end(&mut content) {
                                Err(err) => panic!("Error reading file {}: {}", display, err),
                                Ok(_) => { },
                            }

                            let entry_buffer = EntryBuffer::new(None);
                            let entry = Entry::with_buffer(&entry_buffer);
                            entry.set_visibility(false);
                            entry.show();
                            let flags = DialogFlags::empty();
                            let pass_dialog = MessageDialog::new(Some(&window), flags, MessageType::Question, ButtonsType::OkCancel, "Decryption key:");
                            let content_area = pass_dialog.get_content_area();
                            content_area.pack_start(&entry, true, true, 0);
                            pass_dialog.connect_response(glib::clone!(@weak entry_buffer, @strong sender => move |_, resp| {
                                if resp == ResponseType::Ok.into() {
                                    let key = entry_buffer.get_text();
                                    entry_buffer.delete_text(0, Some(entry_buffer.get_length()));
                                    sender.send(state::Action::Decrypt(key, content.clone())).unwrap();
                                }
                            }));
                            pass_dialog.run();
                            pass_dialog.close();
                        }
                    }
                }
            }));
            dialog.run();
            dialog.close();
        }));

        save_file_as.connect_activate(glib::clone!(@strong window, @strong self.sender as sender => move |_| {
            let dialog = FileChooserDialog::new(Some("Saving file..."), Some(&window), FileChooserAction::Save);
            dialog.add_button("Save", ResponseType::Ok.into());
            dialog.add_button("Cancel", ResponseType::Cancel.into());
            dialog.connect_response(glib::clone!(@weak window, @weak text_buffer, @strong sender => move |dialog, resp| {
                if resp == ResponseType::Ok.into() {
                    if let Some(path) = dialog.get_filename() {
                        let entry_buffer = EntryBuffer::new(None);
                        let entry = Entry::with_buffer(&entry_buffer);
                        entry.set_visibility(false);
                        entry.show();
                        let flags = DialogFlags::empty();
                        let pass_dialog = MessageDialog::new(Some(&window), flags, MessageType::Question, ButtonsType::OkCancel, "Encryption key:");
                        let content_area = pass_dialog.get_content_area();
                        content_area.pack_start(&entry, true, true, 0);
                        pass_dialog.connect_response(glib::clone!(@weak entry_buffer, @weak text_buffer, @strong sender => move |_, resp| {
                            if resp == ResponseType::Ok.into() {
                                let start = text_buffer.get_start_iter();
                                let end  = text_buffer.get_end_iter();
                                if let Some(plaintext) = text_buffer.get_text(&start, &end, false) {
                                    let key = entry_buffer.get_text();
                                    entry_buffer.delete_text(0, Some(entry_buffer.get_length()));
                                    sender.send(state::Action::Encrypt(key, plaintext.to_string(), path.clone())).unwrap();
                                }
                            }
                        }));
                        pass_dialog.run();
                        pass_dialog.close();
                    }
                }
            }));
            dialog.run();
            dialog.close();
        }));

        close.connect_activate(glib::clone!(@strong window => move |_| {
            close_handler!(window);
        }));

        let scroll_window = ScrolledWindow::new(None::<&Adjustment>, None::<&Adjustment>);
        scroll_window.set_policy(PolicyType::Never, PolicyType::Automatic);
        scroll_window.add(&text_view);

        v_box.pack_start(&menu, false, false, 0);
        v_box.pack_start(&self.label, false, true, 0);
        v_box.pack_start(&scroll_window, true, true, 0);
        window.add(&v_box);
        window.show_all();
    }
}
