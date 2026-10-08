// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
// Spike S-1: the Steps widget. It owns no copy of the module. The text lives in Theia's document
// model (a MonacoEditorModel), as D9 asks, so undo, dirty state and save are the model's.
//
// Rendering reuses `ide/` unchanged: `buildHandlerViewModels` and `renderHandlersHtml` from
// `ide/src/stepsModel.ts` build the rows, and `ide/media/stepsWebview.js` runs inside a sandboxed
// iframe behind an `acquireVsCodeApi` shim that forwards its messages here.

import { BaseWidget, DelegatingSaveable, Message, SaveableSource } from '@theia/core/lib/browser';
import { DisposableCollection } from '@theia/core/lib/common/disposable';
import URI from '@theia/core/lib/common/uri';
import { inject, injectable } from '@theia/core/shared/inversify';
import { MonacoEditorModel } from '@theia/monaco/lib/browser/monaco-editor-model';
import { MonacoTextModelService } from '@theia/monaco/lib/browser/monaco-text-model-service';
import {
    addMenuGroups,
    buildEditRequest,
    buildHandlerViewModels,
    escapeHtml,
    LensParseResult,
    parseRewriteResult,
    renderHandlersHtml,
    renderStepsContextMenuHtml,
    rewriteRefusalMessage,
    roleScopeAttr,
    type EditMessage,
    type OpSchema,
} from '../../../../ide/src/stepsModel';
import { StepsLensService } from '../common/steps-protocol';

export const StepsWidgetOptions = Symbol('StepsWidgetOptions');
export interface StepsWidgetOptions {
    uri: string;
}

/** What the spike records for its own measurement (read by the Playwright smoke test). */
export interface StepsSpikeEvent {
    at: number;
    kind: 'render' | 'render-error' | 'edit' | 'edit-refused' | 'undo' | 'redo' | 'webview' | 'unsupported' | 'panel-message';
    detail?: string;
}

declare global {
    interface Window {
        __mfStepsSpike?: StepsSpikeEvent[];
    }
}

@injectable()
export class StepsWidget extends BaseWidget implements SaveableSource {
    static readonly FACTORY_ID = 'mf-steps-spike';

    /** Open Steps views, most recently activated last. FR-17 sends a message to the last visible one. */
    protected static readonly instances: StepsWidget[] = [];

    /** The Steps view a message should land in, or undefined when none is showing. */
    static panelTarget(): StepsWidget | undefined {
        const visible = StepsWidget.instances.filter(w => w.isVisible && w.isAttached);
        return visible[visible.length - 1];
    }

    /** Set by the analyst module only. A developer build keeps the text-editor controls. */
    static analystBuild = false;

    protected touch(): void {
        const list = StepsWidget.instances;
        const at = list.indexOf(this);
        if (at !== -1) {
            list.splice(at, 1);
        }
        if (!this.isDisposed) {
            list.push(this);
        }
    }

    @inject(StepsWidgetOptions) protected readonly options!: StepsWidgetOptions;
    @inject(StepsLensService) protected readonly lens!: StepsLensService;
    @inject(MonacoTextModelService) protected readonly textModels!: MonacoTextModelService;

    protected model: MonacoEditorModel | undefined;
    protected readonly banner = document.createElement('div');
    protected readonly messages = document.createElement('div');
    protected readonly frame = document.createElement('iframe');
    protected readonly modelDisposables = new DisposableCollection();
    protected assets: { script: string; style: string } | undefined;
    protected schema: OpSchema | undefined;
    protected schemaFetched = false;
    protected renderTimer: number | undefined;
    protected renderSeq = 0;
    protected editing = false;
    /** An edit posted while another is in flight. Only the latest is kept; it runs when the slot frees. */
    protected pendingEdit: EditMessage | undefined;

    get uri(): URI {
        return new URI(this.options.uri);
    }

    // The tab's dirty marker, Ctrl+S and the close prompt all come from the document model.
    readonly saveable = new DelegatingSaveable();

    getResourceUri(): URI {
        return this.uri;
    }

    createMoveToUri(resourceUri: URI): URI {
        return resourceUri;
    }

    protected record(kind: StepsSpikeEvent['kind'], detail?: string): void {
        (window.__mfStepsSpike ??= []).push({ at: Date.now(), kind, detail });
        this.node.dataset.mfLast = kind;
    }

    async initialize(): Promise<void> {
        this.id = `${StepsWidget.FACTORY_ID}:${this.options.uri}`;
        this.title.label = `${this.uri.path.base} (Steps)`;
        this.title.caption = this.uri.path.toString();
        this.title.closable = true;
        this.addClass('mf-steps-widget');
        this.node.style.display = 'flex';
        this.node.style.flexDirection = 'column';
        this.banner.className = 'mf-steps-banner';
        this.banner.setAttribute('role', 'status');
        this.banner.style.padding = '4px 8px';
        // allow-scripts without allow-same-origin: the webview runs in an opaque origin and can reach
        // the host only through postMessage, which is all `acquireVsCodeApi` ever gave it.
        this.frame.setAttribute('sandbox', 'allow-scripts');
        this.frame.setAttribute('title', 'Steps');
        this.frame.style.flex = '1';
        this.frame.style.border = 'none';
        this.frame.style.width = '100%';
        // FR-17: messages for the analyst land here, under the banner, not in a pop-up.
        this.messages.className = 'mf-steps-messages';
        this.messages.setAttribute('role', 'log');
        this.messages.setAttribute('aria-live', 'polite');
        this.messages.style.padding = '0 8px';
        this.node.append(this.banner, this.messages, this.frame);
        this.toDispose.push(this.modelDisposables);
        this.toDispose.push({
            dispose: () => {
                if (this.renderTimer !== undefined) {
                    window.clearTimeout(this.renderTimer);
                }
                this.model = undefined;
            },
        });

        const onMessage = (ev: MessageEvent) => {
            // The sandboxed srcdoc has an opaque origin, which a message reports as the string 'null'.
            if (ev.source !== this.frame.contentWindow || ev.origin !== 'null') {
                return;
            }
            const data = ev.data as { mfSteps?: unknown } | undefined;
            if (data && typeof data === 'object' && data.mfSteps && typeof data.mfSteps === 'object') {
                void this.onWebviewMessage(data.mfSteps as { command?: unknown });
            }
        };
        window.addEventListener('message', onMessage);
        this.toDispose.push({ dispose: () => window.removeEventListener('message', onMessage) });

        const ref = await this.textModels.createModelReference(this.uri);
        this.modelDisposables.push(ref);
        this.model = ref.object;
        this.saveable.delegate = this.model;
        // A change from any source (this widget's edit, undo, redo, a revert) re-projects. Debounced so
        // one edit renders once.
        this.modelDisposables.push(this.model.onDidChangeContent(() => this.scheduleRender()));
        this.modelDisposables.push(this.model.onDirtyChanged(() => this.updateSummary()));
        await this.render();
        // Registered only once the widget is whole, so a failed initialize leaves nothing behind.
        this.touch();
        this.toDispose.push({ dispose: () => this.touch() });
    }

    protected onActivateRequest(msg: Message): void {
        super.onActivateRequest(msg);
        this.touch();
        this.frame.focus();
    }

    /**
     * FR-17: show a message in this panel. The newest is on top and the list keeps the last five, so a
     * burst does not push the steps off screen. Each has a Dismiss button, so nothing needs a pop-up.
     */
    showPanelMessage(kind: 'info' | 'warning' | 'error', text: string): void {
        const item = document.createElement('div');
        item.className = `mf-steps-message mf-steps-message-${kind}`;
        item.dataset.kind = kind;
        item.style.display = 'flex';
        item.style.gap = '8px';
        item.style.padding = '2px 0';
        item.style.color = kind === 'error' ? 'var(--theia-errorForeground)'
            : kind === 'warning' ? 'var(--theia-editorWarning-foreground)' : 'var(--theia-foreground)';
        const span = document.createElement('span');
        span.textContent = text;
        span.style.flex = '1';
        const dismiss = document.createElement('button');
        dismiss.className = 'theia-button secondary';
        dismiss.textContent = 'Dismiss';
        dismiss.addEventListener('click', () => item.remove());
        item.append(span, dismiss);
        this.messages.prepend(item);
        while (this.messages.childElementCount > 5) {
            this.messages.lastElementChild?.remove();
        }
        this.record('panel-message', `${kind}: ${text}`.slice(0, 200));
    }

    protected scheduleRender(): void {
        if (this.renderTimer !== undefined) {
            window.clearTimeout(this.renderTimer);
        }
        this.renderTimer = window.setTimeout(() => {
            this.renderTimer = undefined;
            void this.render();
        }, 150);
    }

    protected showBanner(text: string, isError: boolean): void {
        this.banner.textContent = text;
        this.banner.style.color = isError ? 'var(--theia-errorForeground)' : 'var(--theia-descriptionForeground)';
    }

    protected summary = '';

    protected updateSummary(): void {
        if (this.summary) {
            this.showBanner(`${this.summary}${this.model?.dirty ? ' Unsaved changes.' : ''}`, false);
        }
    }

    async render(): Promise<void> {
        try {
            await this.doRender();
        } catch (e) {
            this.showBanner(`The Steps view could not be shown. ${e instanceof Error ? e.message : String(e)}`, true);
            this.record('render-error', String(e));
        }
    }

    protected async doRender(): Promise<void> {
        if (!this.model) {
            return;
        }
        // A later render supersedes this one; a parse that resolves late must not overwrite it.
        const seq = ++this.renderSeq;
        const current = () => seq === this.renderSeq && this.model !== undefined;
        const source = this.model.getText();
        if (!this.schemaFetched) {
            this.schemaFetched = true;
            const sch = await this.lens.schema();
            if (sch.code === 0) {
                try {
                    this.schema = JSON.parse(sch.stdout) as OpSchema;
                } catch {
                    this.schema = undefined; // every param falls back to a text input, as in ide/
                }
            }
        }
        const res = await this.lens.parse(source);
        if (!current()) {
            return;
        }
        if (res.code !== 0) {
            this.showBanner(`The Steps view could not read this file. ${res.stderr.trim().split('\n').pop() ?? ''}`, true);
            this.record('render-error', res.stderr.slice(0, 400));
            return;
        }
        let parsed: LensParseResult;
        try {
            parsed = JSON.parse(res.stdout) as LensParseResult;
        } catch (e) {
            this.showBanner('The Steps view got an answer it could not read.', true);
            this.record('render-error', String(e));
            return;
        }
        const handlers = buildHandlerViewModels(parsed, source);
        this.assets ??= await this.lens.webviewAssets();
        if (!current()) {
            return;
        }
        this.frame.srcdoc = this.pageHtml(renderHandlersHtml(handlers, this.schema));
        const rows = handlers.reduce((n, h) => n + h.rows.length, 0);
        this.node.dataset.mfRows = String(rows);
        this.summary = `${handlers.length} definitions, ${rows} steps.`;
        this.updateSummary();
        this.record('render', `${handlers.length}/${rows}`);
    }

    /**
     * The `--vscode-*` theme variables the reused CSS and script read, mapped to Theia's own
     * `--theia-*` variables. An iframe inherits no custom properties from its parent, so the values are
     * copied in. Theia names a colour `--theia-` plus its colour id with dots as dashes, which is the
     * same id VS Code uses, so the mapping is by name.
     */
    protected themeShim(): string {
        const names = new Set<string>();
        const text = `${this.assets?.style ?? ''}\n${this.assets?.script ?? ''}`;
        for (const m of text.matchAll(/--vscode-([A-Za-z0-9-]+)/g)) {
            names.add(m[1]);
        }
        const computed = getComputedStyle(document.body);
        const special: Record<string, string> = {
            'font-family': '--theia-ui-font-family',
            'editor-font-family': '--theia-code-font-family',
        };
        const decls: string[] = [];
        for (const name of names) {
            const value = computed.getPropertyValue(special[name] ?? `--theia-${name}`).trim();
            if (value) {
                decls.push(`--vscode-${name}: ${value};`);
            }
        }
        return `:root { ${decls.join(' ')} } body { background: ${computed.getPropertyValue('--theia-editor-background').trim()}; }`;
    }

    /** The page shell. The toolbar markup mirrors `pageHtml` in `ide/src/stepsView.ts`, which is not importable. */
    protected pageHtml(body: string): string {
        const insertOptions = ['<option value="">[select item]</option>'].concat(
            addMenuGroups().map(({ group, items }) =>
                `<optgroup label="${escapeHtml(group)}">` +
                items.map(item =>
                    `<option value="${escapeHtml(item.id)}"` +
                    (item.anchorConstraint ? ` data-anchor="${escapeHtml(item.anchorConstraint)}"` : '') +
                    ` data-role-scope="${escapeHtml(roleScopeAttr(item))}">${escapeHtml(item.label)}</option>`
                ).join('') + '</optgroup>'),
        ).join('');
        // The shim is the whole host API the webview script uses: postMessage, getState, setState.
        const shim = `window.acquireVsCodeApi = function () {
  var state;
  return {
    postMessage: function (m) { parent.postMessage({ mfSteps: m }, '*'); },
    getState: function () { return state; },
    setState: function (s) { state = s; }
  };
};`;
        const bytes = new Uint8Array(16);
        crypto.getRandomValues(bytes);
        const nonce = Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
        // A literal "</script>" inside the reused script would end the inline element early.
        const script = (this.assets?.script ?? '').replace(/<\/script/gi, '<\\/script');
        return `<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8" />
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'nonce-${nonce}';" />
<style>${this.themeShim()}</style>
<style>${this.assets?.style ?? ''}</style>
${StepsWidget.analystBuild
        // S-2: the analyst build has no text editor, so the per-row jump-to-line control is hidden (FR-14).
        ? '<style>button.jump { display: none !important; }</style>' : ''}
</head><body>
  <div class="bar">
    <span><input id="stepsFilter" type="search" placeholder="Filter steps" /></span>
    <span class="sep"></span>
    <span><select id="insertAction" aria-label="Insert action">${insertOptions}</select></span>
    <button id="addAction" disabled>Add</button>
    <button id="pickSample">Pick Sample</button>
    <button id="test">Test</button>
    ${StepsWidget.analystBuild ? '<button id="openText" class="link" hidden></button>' : '<button id="openText" class="link">View as Code</button>'}
  </div>
  ${body}
  ${renderStepsContextMenuHtml()}
  <script nonce="${nonce}">${shim}</script>
  <script nonce="${nonce}">${script}</script>
</body></html>`;
    }

    protected async onWebviewMessage(msg: { command?: unknown }): Promise<void> {
        switch (msg.command) {
            case 'stepsDiag':
                this.record('webview', JSON.stringify(msg).slice(0, 200));
                return;
            case 'edit':
                await this.applyEdit(msg as EditMessage);
                return;
            case 'undo':
                if (this.editing) {
                    return; // the in-flight rewrite would otherwise overwrite the undone text
                }
                this.model?.undo();
                this.record('undo');
                return;
            case 'redo':
                if (this.editing) {
                    return;
                }
                this.model?.redo();
                this.record('redo');
                return;
            case 'openText':
            case 'openSource':
                if (StepsWidget.analystBuild) {
                    // ide/ opens the text editor here. The analyst build has none (FR-14), and the webview
                    // controls that post these are hidden, so this is reached only by a forged message.
                    this.record('unsupported', String(msg.command));
                    this.showPanelMessage('info', 'Routers and Handlers open in the Steps view only. Ask a developer if the change needs code.');
                    return;
                }
            // falls through: a developer build would open the text editor, which no spike implements yet
            default:
                // Every other host message (structural ops, Test, pick sample) is outside S-1 and S-2.
                this.record('unsupported', String(msg.command));
                this.showPanelMessage('info', 'That action is not available in this prototype yet.');
        }
    }

    /**
     * One `set_params` edit, ADR 0076 section 5: rewrite the live buffer through the engine, then
     * replace the model's text as ONE undoable edit. pushEditOperations puts it on the model's undo
     * stack, so the model's undo reverts it.
     */
    async applyEdit(msg: EditMessage): Promise<void> {
        const model = this.model;
        if (!model) {
            return;
        }
        if (this.editing) {
            // VS Code queues a racing edit (drainEdits, F5). Keep the latest and run it after this one.
            this.pendingEdit = msg;
            return;
        }
        if (model.readOnly) {
            this.showBanner('This file is read-only, so the Steps view cannot change it.', true);
            this.record('edit-refused', 'read-only');
            await this.render();
            return;
        }
        if (typeof msg.handler !== 'string' || typeof msg.name !== 'string'
            || typeof msg.lineStart !== 'number' || typeof msg.lineEnd !== 'number') {
            this.record('edit-refused', 'malformed edit message');
            return;
        }
        this.editing = true;
        try {
            const before = model.getText();
            const version = model.textEditorModel.getVersionId();
            const res = await this.lens.rewrite(before, buildEditRequest(msg));
            if (this.model !== model) {
                return; // the widget closed while the rewrite ran
            }
            if (model.textEditorModel.getVersionId() !== version) {
                // The text changed while python ran. Writing the result would overwrite that change.
                this.showBanner('The file changed while the edit was applied. Make the change again.', true);
                this.record('edit-refused', 'changed during rewrite');
                await this.render();
                return;
            }
            const outcome = parseRewriteResult(res);
            if (outcome.source === undefined) {
                this.showBanner(`Could not apply the edit. ${rewriteRefusalMessage(outcome)}`, true);
                this.record('edit-refused', outcome.error);
                await this.render();
                return;
            }
            if (outcome.source === model.getText()) {
                return;
            }
            const text = model.textEditorModel;
            text.pushStackElement();
            text.pushEditOperations([], [{ range: text.getFullModelRange(), text: outcome.source }], () => null);
            text.pushStackElement();
            this.record('edit', `${msg.handler}:${msg.lineStart} ${msg.name}`);
        } finally {
            this.editing = false;
        }
        const next = this.pendingEdit;
        this.pendingEdit = undefined;
        if (next) {
            // Its coordinates came from the projection before this edit. A set_params edit keeps line
            // counts, and the engine's expect_src check refuses it if the row no longer matches.
            await this.applyEdit(next);
        }
    }
}
