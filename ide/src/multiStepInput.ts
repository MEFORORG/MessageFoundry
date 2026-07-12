// The official VS Code "multi-step input" helper (adapted from the vscode-extension-samples
// `quickinput-sample/src/multiStepInput.ts`), typed for strict mode. It drives a chain of QuickPick /
// InputBox steps with Back navigation: each step function returns the next step (or calls
// `input.back()` semantics implicitly via the shared InputFlowAction). Used by connectionQuickInput.ts
// for the keyboard-first new-connection wizard (#221e). Pure UI plumbing — no MessageFoundry logic.
import {
  Disposable,
  QuickInput,
  QuickInputButton,
  QuickInputButtons,
  QuickPickItem,
  window,
} from "vscode";

/** A control-flow signal thrown to unwind the step chain: the user hit Back, cancelled, or resumed. */
export class InputFlowAction {
  private constructor() {}
  static back = new InputFlowAction();
  static cancel = new InputFlowAction();
  static resume = new InputFlowAction();
}

/** One step: given the running MultiStepInput, drive a prompt and return the next step (or void to end). */
export type InputStep = (input: MultiStepInput) => Thenable<InputStep | void>;

interface QuickPickParameters<T extends QuickPickItem> {
  title: string;
  step: number;
  totalSteps: number;
  items: T[];
  activeItem?: T;
  placeholder: string;
  buttons?: QuickInputButton[];
  shouldResume?: () => Thenable<boolean>;
}

interface InputBoxParameters {
  title: string;
  step: number;
  totalSteps: number;
  value: string;
  prompt: string;
  password?: boolean;
  buttons?: QuickInputButton[];
  validate: (value: string) => Promise<string | undefined>;
  shouldResume?: () => Thenable<boolean>;
}

export class MultiStepInput {
  /**
   * Drive the step chain and resolve with whether it COMPLETED — i.e. a step returned normally with no
   * next step (the wizard finished) — versus was dismissed (Esc/cancel, or Back off the first step).
   * Callers gate their write on this: cancel at any step resolves `false`, so no partial write. The
   * step functions still throw {@link InputFlowAction} internally; that is unwound here, not surfaced.
   */
  static async run(start: InputStep): Promise<boolean> {
    const input = new MultiStepInput();
    return input.stepThrough(start);
  }

  private current?: QuickInput;
  private steps: InputStep[] = [];

  private async stepThrough(start: InputStep): Promise<boolean> {
    let step: InputStep | void = start;
    let completed = false;
    while (step) {
      this.steps.push(step);
      if (this.current) {
        this.current.enabled = false;
        this.current.busy = true;
      }
      try {
        const next = await step(this);
        // A step that returns no next step ran the chain to its end → the wizard completed. A cancel
        // (below) instead sets `step = undefined` WITHOUT flipping this, so it stays a dismissal.
        completed = !next;
        step = next;
      } catch (err) {
        if (err === InputFlowAction.back) {
          this.steps.pop();
          step = this.steps.pop();
        } else if (err === InputFlowAction.resume) {
          step = this.steps.pop();
        } else if (err === InputFlowAction.cancel) {
          step = undefined;
        } else {
          throw err;
        }
      }
    }
    if (this.current) {
      this.current.dispose();
    }
    return completed;
  }

  /** Show a QuickPick and resolve with the chosen item; throws an InputFlowAction on Back/cancel. */
  async showQuickPick<T extends QuickPickItem, P extends QuickPickParameters<T>>({
    title,
    step,
    totalSteps,
    items,
    activeItem,
    placeholder,
    buttons,
    shouldResume,
  }: P): Promise<T> {
    const disposables: Disposable[] = [];
    try {
      return await new Promise<T>((resolve, reject) => {
        const input = window.createQuickPick<T>();
        input.title = title;
        input.step = step;
        input.totalSteps = totalSteps;
        input.placeholder = placeholder;
        input.items = items;
        if (activeItem) {
          input.activeItems = [activeItem];
        }
        input.buttons = [...(this.steps.length > 1 ? [QuickInputButtons.Back] : []), ...(buttons ?? [])];
        disposables.push(
          input.onDidTriggerButton((item) => {
            if (item === QuickInputButtons.Back) {
              reject(InputFlowAction.back);
            }
          }),
          input.onDidChangeSelection((selection) => {
            if (selection[0]) {
              resolve(selection[0]);
            }
          }),
          input.onDidHide(() => {
            void (async (): Promise<void> => {
              reject(
                (shouldResume && (await shouldResume())) ? InputFlowAction.resume : InputFlowAction.cancel,
              );
            })();
          }),
        );
        if (this.current) {
          this.current.dispose();
        }
        this.current = input;
        this.current.show();
      });
    } finally {
      disposables.forEach((d) => d.dispose());
    }
  }

  /** Show an InputBox and resolve with the entered value; throws an InputFlowAction on Back/cancel. */
  async showInputBox<P extends InputBoxParameters>({
    title,
    step,
    totalSteps,
    value,
    prompt,
    password,
    buttons,
    validate,
    shouldResume,
  }: P): Promise<string> {
    const disposables: Disposable[] = [];
    try {
      return await new Promise<string>((resolve, reject) => {
        const input = window.createInputBox();
        input.title = title;
        input.step = step;
        input.totalSteps = totalSteps;
        input.value = value ?? "";
        input.prompt = prompt;
        input.password = password ?? false;
        input.ignoreFocusOut = true;
        input.buttons = [...(this.steps.length > 1 ? [QuickInputButtons.Back] : []), ...(buttons ?? [])];
        let validating = validate("");
        disposables.push(
          input.onDidTriggerButton((item) => {
            if (item === QuickInputButtons.Back) {
              reject(InputFlowAction.back);
            }
          }),
          input.onDidAccept(() => {
            void (async (): Promise<void> => {
              const v = input.value;
              input.enabled = false;
              input.busy = true;
              if (!(await validate(v))) {
                resolve(v);
              }
              input.enabled = true;
              input.busy = false;
            })();
          }),
          input.onDidChangeValue((text) => {
            void (async (): Promise<void> => {
              const current = validate(text);
              validating = current;
              const validationMessage = await current;
              if (current === validating) {
                input.validationMessage = validationMessage;
              }
            })();
          }),
          input.onDidHide(() => {
            void (async (): Promise<void> => {
              reject(
                (shouldResume && (await shouldResume())) ? InputFlowAction.resume : InputFlowAction.cancel,
              );
            })();
          }),
        );
        if (this.current) {
          this.current.dispose();
        }
        this.current = input;
        this.current.show();
        void validating;
      });
    } finally {
      disposables.forEach((d) => d.dispose());
    }
  }
}
