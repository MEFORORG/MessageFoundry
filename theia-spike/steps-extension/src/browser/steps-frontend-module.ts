// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
import { OpenHandler, WidgetFactory, WidgetOpenHandler } from '@theia/core/lib/browser';
import { ServiceConnectionProvider } from '@theia/core/lib/browser/messaging/service-connection-provider';
import URI from '@theia/core/lib/common/uri';
import { ContainerModule, injectable } from '@theia/core/shared/inversify';
import { STEPS_LENS_PATH, StepsLensService } from '../common/steps-protocol';
import { isStepsUri } from './analyst-routes';
import { StepsWidget, StepsWidgetOptions } from './steps-widget';

/**
 * Opens a `.py` on disk in the Steps widget. Priority 500 beats the text editor's default (100), so
 * the navigator's open goes here. The analyst build makes it the ONLY route (analyst-frontend-module).
 */
@injectable()
export class StepsOpenHandler extends WidgetOpenHandler<StepsWidget> {
    readonly id = StepsWidget.FACTORY_ID;
    readonly label = 'Steps';

    canHandle(uri: URI): number {
        return isStepsUri(uri) ? 500 : 0;
    }

    protected createWidgetOptions(uri: URI): StepsWidgetOptions {
        return { uri: uri.withoutFragment().toString() };
    }
}

export default new ContainerModule(bind => {
    bind(StepsLensService).toDynamicValue(ctx =>
        ServiceConnectionProvider.createProxy<StepsLensService>(ctx.container, STEPS_LENS_PATH)
    ).inSingletonScope();

    bind(WidgetFactory).toDynamicValue(ctx => ({
        id: StepsWidget.FACTORY_ID,
        createWidget: async (options: StepsWidgetOptions) => {
            const child = ctx.container.createChild();
            child.bind(StepsWidgetOptions).toConstantValue(options);
            child.bind(StepsWidget).toSelf();
            const widget = child.get(StepsWidget);
            await widget.initialize();
            return widget;
        },
    })).inSingletonScope();

    bind(StepsOpenHandler).toSelf().inSingletonScope();
    bind(OpenHandler).toService(StepsOpenHandler);
});
