use std::sync::{Mutex, OnceLock};
use crate::classes::{Poll, PollController, PollResult};
use crate::AppWindow;
use slint::{ModelRc, SharedString, VecModel};

const SEP: char = '\u{1}';
static CONTROLLER: OnceLock<Mutex<PollController>> = OnceLock::new();

pub fn controller() -> &'static Mutex<PollController> {CONTROLLER.get_or_init(|| Mutex::new(PollController::default()))}
fn clean(text: &str) -> String {text.chars().filter(|c| !c.is_control()).collect::<String>().trim().to_string()}

impl PollController {
    /// Called when the dialog's Create is pressed.
    /// Returns the POLL packet to send, or None if a poll is already open or the input is invalid.
    pub fn create_poll(&mut self, creator_id: &str, minutes: i32, question: &str, options: &[String],) -> Option<String> {
        if self.current.is_some() { return None; /* only one open poll at a time */  }

        let question = clean(question);
        let options: Vec<String> = options.iter().map(|o| clean(o)).filter(|o| !o.is_empty()).collect();
        if question.is_empty() || options.len() < 2 {return None;}
        let poll = Poll {id: new_poll_id(), creator_id: creator_id.to_string(), minutes: minutes.clamp(1, 5), question, options,};

        let mut packet = format!("POLL{}{SEP}{}{SEP}{}{SEP}{}", poll.id, poll.creator_id, poll.minutes, poll.question);
        for option in &poll.options {
            packet.push(SEP);
            packet.push_str(option);
        }

        Some(packet)
    }
}

fn new_poll_id() -> String {
    use rand::Rng;
    let mut bytes = [0u8; 16];
    rand::rng().fill(&mut bytes);
    hex::encode(bytes)
}

pub fn handle_poll_packet(payload: &str) -> bool {
    let fields: Vec<&str> = payload.split(SEP).collect();
    if fields.len() < 5 {return false;}
    let id = fields[0];
    let creator_id = fields[1];
    let minutes = match fields[2].parse::<i32>() {Ok(value) if (1..=5).contains(&value) => value,_ => return false,};
    let question = clean(fields[3]);
    let options: Vec<String> = fields[4..].iter().map(|option| clean(option)).filter(|option| !option.is_empty()).collect();
    if id.is_empty() || creator_id.is_empty() || question.is_empty() || options.len() < 2 {return false;}
    let poll = Poll {id: id.to_string(), creator_id: creator_id.to_string(), minutes, question, options,};
    let mut controller = controller().lock().unwrap();
    // Only one open poll at a time.
    if controller.current.is_some() { return false; }
    controller.current = Some(poll);
    controller.seconds_left = minutes * 60;
    controller.votes.clear();
    true
}

// couldn't figure out a way to not use the ui here but in main so kept it here
pub fn show_poll(ui_weak: slint::Weak<AppWindow>) {
    let (poll, my_id) = {
        let controller = controller().lock().unwrap();
        (controller.current.clone(), controller.my_id.clone())
    };
    let Some(poll) = poll else {return;};
    let is_creator = poll.creator_id == my_id;

    let _ = slint::invoke_from_event_loop(move || {
        let Some(app) = ui_weak.upgrade() else {return;};
        let options: Vec<SharedString> = poll.options.iter().map(|option| option.as_str().into()).collect();
        let counts = vec![0i32; poll.options.len()];
        app.set_poll_question(poll.question.as_str().into());
        app.set_poll_options(ModelRc::new(VecModel::from(options)));
        app.set_poll_counts(ModelRc::new(VecModel::from(counts)));
        app.set_poll_countdown(format!("{}:00", poll.minutes).into());
        app.set_poll_is_creator(is_creator);
        app.set_poll_active(true);
    });
}


// manually setting the id so we can use it to compare if it is the poll creator or no
pub fn set_my_id(id: String) {
    controller().lock().unwrap().my_id = id;
}

/// Builds the VOTE packet for the tapped option, or None if there is no open poll.
pub fn build_vote_packet(option_index: i32) -> Option<String> {
    let controller = controller().lock().unwrap();
    let poll = controller.current.as_ref()?;
    if option_index < 0 || option_index as usize >= poll.options.len() { return None; }
    Some(format!("VOTE{}{SEP}{}{SEP}{}", poll.id, controller.my_id, option_index))
}

/// Returns true if the tally changed.
pub fn handle_vote_packet(payload: &str) -> bool {
    let fields: Vec<&str> = payload.split(SEP).collect();
    if fields.len() != 3 { return false; }
    let (poll_id, voter_id) = (fields[0], fields[1]);
    let Ok(index) = fields[2].parse::<usize>() else { return false; };
    if voter_id.is_empty() { return false; }

    let mut controller = controller().lock().unwrap();
    let (option_count, minutes) = match &controller.current {
        Some(poll) if poll.id == poll_id => (poll.options.len(), poll.minutes),_ => return false,};
    if index >= option_count { return false; }
    // 2nd and 3rd copies of the same vote change nothing
    if controller.votes.get(voter_id) == Some(&index) { return false; }
    let is_new_voter = !controller.votes.contains_key(voter_id);
    controller.votes.insert(voter_id.to_string(), index);
    // only a new voter's first vote resets the timer
    if is_new_voter { controller.seconds_left = minutes * 60; }
    true
}

pub fn update_counts(ui_weak: slint::Weak<AppWindow>) {
    let counts = {
        let controller = controller().lock().unwrap();
        let Some(poll) = controller.current.as_ref() else { return; };
        let mut counts = vec![0i32; poll.options.len()];
        for &i in controller.votes.values() { counts[i] += 1; }
        counts
    };
    let _ = slint::invoke_from_event_loop(move || {
        if let Some(app) = ui_weak.upgrade() {app.set_poll_counts(ModelRc::new(VecModel::from(counts)));}
    });
}

pub fn start_countdown(ui_weak: slint::Weak<AppWindow>) {
    let poll_id = match &controller().lock().unwrap().current {Some(poll) => poll.id.clone(), None => return,};
    std::thread::spawn(move || loop {
        std::thread::sleep(std::time::Duration::from_secs(1));
        let seconds = {
            let mut controller = controller().lock().unwrap();
            match &controller.current {Some(poll) if poll.id == poll_id => {}_ => return,}
            if controller.seconds_left > 0 { controller.seconds_left -= 1; }
            controller.seconds_left
        };
        let text = format!("{}:{:02}", seconds / 60, seconds % 60);
        let weak = ui_weak.clone();
        let _ = slint::invoke_from_event_loop(move || {
            if let Some(app) = weak.upgrade() { app.set_poll_countdown(text.into()); }
        });
        if seconds == 0 {
            close_poll(ui_weak);
            return;
        }
    });
}

/// Removes the open poll from `current`, saves its result in memory and returns it.
pub fn finish_poll() -> Option<PollResult> {
    let mut controller = controller().lock().unwrap();
    let poll = controller.current.take()?;
    let mut counts = vec![0i32; poll.options.len()];
    for &i in controller.votes.values() { counts[i] += 1; }
    controller.votes.clear();
    controller.seconds_left = 0;
    let result = PollResult { id: poll.id, question: poll.question, options: poll.options, counts };
    controller.results.insert(result.id.clone(), result.clone());
    Some(result)
}

/// Closes the open poll everywhere on this device: hides the banner and adds the finished message.
pub fn close_poll(ui_weak: slint::Weak<AppWindow>) {
    let Some(result) = finish_poll() else { return; };
    let _ = slint::invoke_from_event_loop(move || {
        if let Some(app) = ui_weak.upgrade() {
            app.set_poll_active(false);
            app.invoke_append_poll_result(format!("📊 Poll finished: {}", result.question).into(), result.id.clone().into(),);
        }
    });
}

/// DNPL packet, only if this device created the open poll.
pub fn build_done_packet() -> Option<String> {
    let controller = controller().lock().unwrap();
    let poll = controller.current.as_ref()?;
    if poll.creator_id != controller.my_id { return None; }
    Some(format!("DNPL{}{SEP}{}", poll.id, poll.creator_id))
}

/// True if the DNPL matches the open poll and comes from its creator.
pub fn handle_done_packet(payload: &str) -> bool {
    let fields: Vec<&str> = payload.split(SEP).collect();
    if fields.len() != 2 { return false; }
    let controller = controller().lock().unwrap();
    matches!(&controller.current, Some(poll) if poll.id == fields[0] && poll.creator_id == fields[1])
}

pub fn get_result(poll_id: &str) -> Option<PollResult> {controller().lock().unwrap().results.get(poll_id).cloned()}
