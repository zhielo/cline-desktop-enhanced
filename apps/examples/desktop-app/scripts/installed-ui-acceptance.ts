// Reuse the existing locked Playwright dependency owned by the VS Code workspace.
import { runAcceptance } from "../../../vscode/scripts/desktop-installed-acceptance";
void runAcceptance();
