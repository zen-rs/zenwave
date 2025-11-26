//! A basic example demonstrating a GET request and JSON deserialization.

use serde::Deserialize;
use zenwave::{self, ResponseExt};

#[derive(Debug, Deserialize)]
struct Todo {
    #[serde(rename = "userId")]
    user_id: u32,
    id: u32,
    title: String,
    completed: bool,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    async_io::block_on(async {
    // `zenwave::get` is perfect for one-off requests.
    let response = zenwave::get("https://jsonplaceholder.typicode.com/todos/1").await?;
    let todo: Todo = response.into_json().await?;

    println!(
        "Todo #{id} for user #{user}: {title} (completed: {completed})",
        id = todo.id,
        user = todo.user_id,
        title = todo.title,
        completed = todo.completed
    );

        Ok(())
    })
}
