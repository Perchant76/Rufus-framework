// src-tauri/src/commands/tools.rs
use crate::scanner::tools;
use crate::db::models::ToolStatus;

#[tauri::command]
pub async fn check_tool_availability(name: String) -> Result<ToolStatus, String> {
    let def = tools::ALL_TOOLS.iter().find(|t| t.name == name)
        .ok_or_else(|| format!("Unknown tool: {}", name))?;
    Ok(tools::check_tool(def))
}

#[tauri::command]
pub async fn check_all_tools() -> Result<Vec<ToolStatus>, String> {
    Ok(tools::check_all())
}
