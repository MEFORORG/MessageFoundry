// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
// Spike S-2: the analyst build's guard. A `.py` opens only in the Steps view (FR-14, AC-G1), and a
// message shown while a Steps view is up goes into that view rather than a pop-up (FR-17).
//
// It is a separate frontend module so a developer build can leave it out and keep the text editor.
// It closes the text route at three layers, because no single one sees every caller:
//   1. the opener: EditorManager.canHandle declines a `.py`, so the Steps handler (500) is the only one;
//   2. the direct callers: EditorManager.open, Open With and the editor widget factory's
//      TextEditorProvider all refuse a `.py`, which catches code that skips the opener (Outline,
//      reopen-closed-editor, workspace edits, layout restore, `workbench.editorAssociations`);
//   3. the commands that reach text with no `.py` in hand yet (New Text File, Save As, Compare,
//      Open With) are never registered, so no menu, palette entry or keybinding can run them.

import {
    ApplicationShell,
    FrontendApplicationContribution,
    KeybindingRegistry,
    KeybindingScope,
    OpenerOptions,
    OpenerService,
    OpenHandler,
    OpenWithHandler,
    OpenWithService,
    WidgetManager,
} from '@theia/core/lib/browser';
import { WebSocketConnectionProvider } from '@theia/core/lib/browser/messaging/ws-connection-provider';
import {
    Command,
    CommandContribution,
    CommandHandler,
    CommandRegistry,
    ContributionProvider,
    Disposable,
    MenuModelRegistry,
    MenuNode,
    MessageClient,
    MessageService,
    MessageType,
    PreferenceScope,
    PreferenceService,
} from '@theia/core/lib/common';
import { CompoundMenuNode } from '@theia/core/lib/common/menu/menu-types';
import { commandServicePath } from '@theia/core/lib/common/command';
import URI from '@theia/core/lib/common/uri';
import { ContainerModule, inject, injectable, interfaces, named } from '@theia/core/shared/inversify';
import { DiffUris } from '@theia/core/lib/browser/diff-uris';
import { EditorManager, EditorOpenerOptions } from '@theia/editor/lib/browser/editor-manager';
import { EditorWidget } from '@theia/editor/lib/browser/editor-widget';
import { EditorWidgetFactory } from '@theia/editor/lib/browser/editor-widget-factory';
import { TextEditorProvider } from '@theia/editor/lib/browser/editor';
import { MonacoEditorProvider } from '@theia/monaco/lib/browser/monaco-editor-provider';
import { WorkspaceService } from '@theia/workspace/lib/browser/workspace-service';
import { BLOCKED_COMMANDS, isPythonUri, isStepsUri, textEditorRefusal } from './analyst-routes';
import { StepsOpenHandler } from './steps-frontend-module';
import { StepsWidget } from './steps-widget';

/** One refused attempt, recorded for the S-2 walk. `layer` names the guard that caught it. */
export interface AnalystRefusal {
    at: number;
    layer: 'editor-manager' | 'open-with' | 'text-editor-provider' | 'command-registry';
    reason: string;
    target: string;
}

const refusals: AnalystRefusal[] = [];

/** Every message that went to the notification client (a toast) rather than a Steps view. */
const toastPath: { at: number; type: string; text: string }[] = [];

function refuse(layer: AnalystRefusal['layer'], reason: string, target: string): void {
    refusals.push({ at: Date.now(), layer, reason, target });
}

/** The `.py` a refused text route was aiming at, so the Steps view can open it instead. */
function stepsTarget(uri: URI): URI | undefined {
    if (DiffUris.isDiffUri(uri)) {
        const sides = DiffUris.decode(uri);
        return sides.slice().reverse().find(isStepsUri);
    }
    return isStepsUri(uri) ? uri : undefined;
}

const REFUSED_TEXT = 'Routers and Handlers open in the Steps view only. Ask a developer if the change needs code.';

/** Layers 1 and 2: the text editor declines every `.py`, and a direct open is sent to the Steps view. */
@injectable()
export class AnalystEditorManager extends EditorManager {
    @inject(StepsOpenHandler) protected readonly stepsOpener!: StepsOpenHandler;

    override canHandle(uri: URI, options?: OpenerOptions): number {
        return textEditorRefusal(uri) ? 0 : super.canHandle(uri, options);
    }

    override async open(uri: URI, options?: EditorOpenerOptions): Promise<EditorWidget> {
        const reason = textEditorRefusal(uri);
        if (reason === undefined) {
            return super.open(uri, options);
        }
        refuse('editor-manager', reason, uri.toString());
        const target = stepsTarget(uri);
        if (target) {
            const widget = await this.stepsOpener.open(target);
            widget.showPanelMessage('info', REFUSED_TEXT);
        } else {
            StepsWidget.panelTarget()?.showPanelMessage('info', REFUSED_TEXT);
        }
        // The caller asked for a text editor and gets none. Throwing is the honest answer: core logs a
        // failed command to the console and raises no notification.
        throw new Error(`The analyst build does not open ${uri.path.base || uri.toString()} in a text editor.`);
    }
}

/** Layer 2: Open With lists no text editor for a guarded URI, and refuses if called anyway. */
@injectable()
export class AnalystOpenWithService extends OpenWithService {
    override getHandlers(uri: URI): OpenWithHandler[] {
        const handlers = super.getHandlers(uri);
        return textEditorRefusal(uri) ? handlers.filter(h => h.id !== 'default' && h.id !== EditorWidgetFactory.ID) : handlers;
    }

    override async openWith(uri: URI): Promise<object | undefined> {
        if (textEditorRefusal(uri)) {
            refuse('open-with', textEditorRefusal(uri) ?? '', uri.toString());
            StepsWidget.panelTarget()?.showPanelMessage('info', REFUSED_TEXT);
            return undefined;
        }
        return super.openWith(uri);
    }
}

/** Layer 3: the blocked commands are never registered, so no menu, palette or keybinding reaches one. */
@injectable()
export class AnalystCommandRegistry extends CommandRegistry {
    constructor(
        @inject(ContributionProvider) @named(CommandContribution)
        contributionProvider: ContributionProvider<CommandContribution>,
    ) {
        super(contributionProvider);
    }

    override registerCommand(command: Command, handler?: CommandHandler): Disposable {
        if (BLOCKED_COMMANDS.has(command.id)) {
            refuse('command-registry', 'blocked command', command.id);
            return Disposable.NULL;
        }
        return super.registerCommand(command, handler);
    }

    override registerHandler(commandId: string, handler: CommandHandler): Disposable {
        if (BLOCKED_COMMANDS.has(commandId)) {
            refuse('command-registry', 'blocked handler', commandId);
            return Disposable.NULL;
        }
        return super.registerHandler(commandId, handler);
    }

    override registerAlias(aliasId: string, targetId: string): Disposable {
        if (BLOCKED_COMMANDS.has(aliasId) || BLOCKED_COMMANDS.has(targetId)) {
            refuse('command-registry', 'blocked alias', `${aliasId}->${targetId}`);
            return Disposable.NULL;
        }
        return super.registerAlias(aliasId, targetId);
    }
}

/**
 * FR-17: while a Steps view is showing, a message goes into it instead of a toast. A message that
 * offers actions gets none here, so its caller sees "dismissed"; that is the spike's known gap.
 */
@injectable()
export class AnalystMessageService extends MessageService {
    constructor(@inject(MessageClient) client: MessageClient) {
        super(client);
    }

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    protected override processMessage(type: MessageType, text: string, args?: any[]): Promise<string | undefined> {
        const target = StepsWidget.panelTarget();
        if (target && type !== MessageType.Log) {
            const kind = type === MessageType.Error ? 'error' : type === MessageType.Warning ? 'warning' : 'info';
            target.showPanelMessage(kind, text);
            return Promise.resolve(undefined);
        }
        if (type !== MessageType.Log) {
            toastPath.push({ at: Date.now(), type: String(type), text: String(text).slice(0, 200) });
        }
        return super.processMessage(type, text, args);
    }
}

interface MenuItemRecord { path: string[]; commandId: string; label: string }

/**
 * Removes any menu item or keybinding a contribution attached to a blocked command, and exposes the
 * S-2 test hook. The hook is spike-only: a shipped build would not put services on `window`.
 */
@injectable()
export class AnalystRoutesContribution implements FrontendApplicationContribution {
    @inject(CommandRegistry) protected readonly commands!: CommandRegistry;
    @inject(MenuModelRegistry) protected readonly menus!: MenuModelRegistry;
    @inject(KeybindingRegistry) protected readonly keybindings!: KeybindingRegistry;
    @inject(EditorManager) protected readonly editors!: EditorManager;
    @inject(OpenerService) protected readonly openers!: OpenerService;
    @inject(OpenWithService) protected readonly openWith!: OpenWithService;
    @inject(WidgetManager) protected readonly widgets!: WidgetManager;
    @inject(ApplicationShell) protected readonly shell!: ApplicationShell;
    @inject(MessageService) protected readonly messages!: MessageService;
    @inject(WorkspaceService) protected readonly workspace!: WorkspaceService;
    @inject(TextEditorProvider) protected readonly textEditorProvider!: TextEditorProvider;
    @inject(PreferenceService) protected readonly preferences!: PreferenceService;

    protected readonly createdEditors: string[] = [];

    onStart(): void {
        this.widgets.onDidCreateWidget(({ widget, factoryId }) => {
            if (widget instanceof EditorWidget || factoryId === EditorWidgetFactory.ID) {
                this.createdEditors.push(widget instanceof EditorWidget ? widget.editor.uri.toString() : widget.id);
            }
        });
        this.removeBlocked();
        this.exposeHook();
    }

    onDidInitializeLayout(): void {
        // A contribution that registers in its own onStart may run after this one; sweep again.
        this.removeBlocked();
    }

    protected removeBlocked(): void {
        for (const id of BLOCKED_COMMANDS.keys()) {
            this.menus.unregisterMenuAction(id);
            // By command id: getKeybindingsForCommand skips a binding whose command is not registered,
            // which is every binding here, so it would find nothing to remove.
            this.keybindings.unregisterKeybinding({ id });
        }
    }

    protected menuItems(): MenuItemRecord[] {
        const out: MenuItemRecord[] = [];
        const walk = (node: MenuNode, path: string[]): void => {
            if (CompoundMenuNode.is(node)) {
                const label = (node as { label?: string }).label ?? node.id;
                for (const child of node.children) {
                    walk(child, [...path, label]);
                }
                return;
            }
            const action = node as MenuNode & { label?: string };
            // An ActionMenuNode's id is its command id.
            out.push({ path, commandId: action.id, label: action.label ?? '' });
        };
        const root = (this.menus as unknown as { root?: MenuNode }).root;
        if (root) {
            walk(root, []);
        }
        return out;
    }

    protected allKeybindings(): { keybinding: string; command: string }[] {
        const out: { keybinding: string; command: string }[] = [];
        for (let scope = KeybindingScope.DEFAULT; scope < KeybindingScope.length; scope++) {
            for (const kb of this.keybindings.getKeybindingsByScope(scope)) {
                out.push({ keybinding: kb.keybinding, command: kb.command });
            }
        }
        return out;
    }

    protected async openerPriorities(uri: URI): Promise<{ id: string; priority: number }[]> {
        const all = await this.openers.getOpeners();
        const out: { id: string; priority: number }[] = [];
        for (const h of all as OpenHandler[]) {
            out.push({ id: h.id, priority: await h.canHandle(uri) });
        }
        return out.filter(o => o.priority > 0).sort((a, b) => b.priority - a.priority);
    }

    protected async settle<T>(p: Promise<T>, ms: number): Promise<string> {
        let timer: number | undefined;
        const timeout = new Promise<string>(resolve => { timer = window.setTimeout(() => resolve('timeout'), ms); });
        try {
            return await Promise.race([p.then(() => 'ok', (e: unknown) => `threw: ${e instanceof Error ? e.message : String(e)}`.slice(0, 300)), timeout]);
        } finally {
            window.clearTimeout(timer);
        }
    }

    protected exposeHook(): void {
        const self = this;
        const root = async (): Promise<URI> => (await this.workspace.roots)[0].resource;
        (window as unknown as { __mfAnalyst: unknown }).__mfAnalyst = {
            refusals,
            toastPath,
            createdEditors: this.createdEditors,
            blocked: [...BLOCKED_COMMANDS.keys()],
            async fileUri(rel: string) { return (await root()).resolve(rel).toString(); },
            commands: () => this.commands.commands.map(c => ({ id: c.id, label: c.label ?? '', category: c.category ?? '' })),
            isEnabled: (id: string) => { try { return this.commands.isEnabled(id); } catch { return false; } },
            hasHandler: (id: string) => this.commands.getAllHandlers(id).length > 0,
            exec: (id: string, ms = 3000) => self.settle(Promise.resolve().then(() => this.commands.executeCommand(id)), ms),
            menuItems: () => this.menuItems(),
            keybindings: () => this.allKeybindings(),
            textEditors: () => this.editors.all.map(w => w.editor.uri.toString()),
            stepsWidgets: () => this.widgets.getWidgets(StepsWidget.FACTORY_ID).map(w => (w as StepsWidget).uri.toString()),
            currentWidget: () => this.shell.currentWidget?.id ?? '',
            openers: (u: string) => this.openerPriorities(new URI(u)),
            openViaOpener: (u: string, line?: number) => self.settle(
                this.openers.getOpener(new URI(u)).then(h => h.open(new URI(u), line === undefined ? undefined
                    : { selection: { start: { line, character: 0 }, end: { line, character: 0 } } } as OpenerOptions)), 10000),
            openViaEditorManager: (u: string, line?: number) => self.settle(this.editors.open(new URI(u), line === undefined ? undefined
                : { selection: { start: { line, character: 0 }, end: { line, character: 0 } } }), 10000),
            openWithHandlers: (u: string) => this.openWith.getHandlers(new URI(u)).map(h => h.id),
            openWith: (u: string) => self.settle(this.openWith.openWith(new URI(u)), 3000),
            editorFactory: (u: string) => self.settle(this.widgets.getOrCreateWidget(EditorWidgetFactory.ID,
                { kind: 'navigatable', uri: u, counter: 9999 }), 10000),
            textEditorProvider: (u: string) => self.settle(this.textEditorProvider(new URI(u)), 10000),
            diffUri: (l: string, r: string) => DiffUris.encode(new URI(l), new URI(r)).toString(),
            message: (type: 'info' | 'warn' | 'error', text: string) => self.settle(Promise.resolve(this.messages[type](text)), 2000),
            isPython: (u: string) => isPythonUri(new URI(u)),
            // Workspace scope, so the setting lands in the test's temporary workspace copy, never the user's.
            setWorkspacePreference: (key: string, value: unknown) => self.settle(
                this.preferences.set(key, value, PreferenceScope.Workspace), 5000),
            activateSteps: async (u?: string) => {
                const target = this.widgets.getWidgets(StepsWidget.FACTORY_ID)
                    .find(w => u === undefined || (w as StepsWidget).uri.toString() === u);
                if (target) {
                    await this.shell.activateWidget(target.id);
                }
                return target?.id ?? '';
            },
        };
    }
}

export default new ContainerModule((bind, unbind, isBound, rebind) => {
    rebind(EditorManager).to(AnalystEditorManager).inSingletonScope();
    rebind(OpenWithService).to(AnalystOpenWithService).inSingletonScope();
    // Keep the core binding's activation hook, which serves frontend commands to the backend.
    rebind(CommandRegistry).to(AnalystCommandRegistry).inSingletonScope().onActivation(({ container }: interfaces.Context, registry: CommandRegistry) => {
        WebSocketConnectionProvider.createHandler(container, commandServicePath, registry);
        return registry;
    });
    rebind(MessageService).to(AnalystMessageService).inSingletonScope();
    rebind(TextEditorProvider).toProvider(ctx => async (uri: URI) => {
        const reason = textEditorRefusal(uri);
        if (reason !== undefined) {
            refuse('text-editor-provider', reason, uri.toString());
            throw new Error(`The analyst build does not create a text editor for ${uri.path.base || uri.toString()}.`);
        }
        return ctx.container.get(MonacoEditorProvider).get(uri);
    });
    bind(AnalystRoutesContribution).toSelf().inSingletonScope();
    bind(FrontendApplicationContribution).toService(AnalystRoutesContribution);
});
