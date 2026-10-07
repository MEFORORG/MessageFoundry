// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
import { ConnectionHandler, RpcConnectionHandler } from '@theia/core/lib/common/messaging';
import { ContainerModule } from '@theia/core/shared/inversify';
import { STEPS_LENS_PATH, StepsLensService } from '../common/steps-protocol';
import { StepsLensServiceImpl } from './steps-lens-service-impl';

export default new ContainerModule(bind => {
    bind(StepsLensServiceImpl).toSelf().inSingletonScope();
    bind(StepsLensService).toService(StepsLensServiceImpl);
    bind(ConnectionHandler).toDynamicValue(ctx =>
        new RpcConnectionHandler(STEPS_LENS_PATH, () => ctx.container.get<StepsLensService>(StepsLensService))
    ).inSingletonScope();
});
