export interface FileFilter {
  name: string;
  extensions: string[];
}

/**
 * Wrap the Tauri dialog plugin so the rest of the UI never imports it directly:
 * tests and browser previews get a null result instead of an IPC failure.
 */
export async function pickFile(title: string, filters?: FileFilter[]): Promise<string | null> {
  try {
    const { open } = await import("@tauri-apps/plugin-dialog");
    const selection: unknown = await open({ title, multiple: false, directory: false, filters });
    if (typeof selection === "string") return selection;
    if (Array.isArray(selection) && typeof selection[0] === "string") return selection[0];
    return null;
  } catch {
    return null;
  }
}

export async function pickSavePath(defaultPath: string, filters?: FileFilter[]): Promise<string | null> {
  try {
    const { save } = await import("@tauri-apps/plugin-dialog");
    const destination: unknown = await save({ title: "Export", defaultPath, filters });
    return typeof destination === "string" ? destination : null;
  } catch {
    return null;
  }
}
