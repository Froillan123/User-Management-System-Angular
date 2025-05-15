import { NgModule } from '@angular/core';
import { CommonModule } from '@angular/common';
import { ReactiveFormsModule, FormsModule } from '@angular/forms';

import { AnalyticsRoutingModule } from './analytics-routing.module';
import { LayoutComponent } from './layout.component';
import { DashboardComponent } from './dashboard.component';
import { UsersOnlineComponent } from './users-online.component';

@NgModule({
    imports: [
        CommonModule,
        ReactiveFormsModule,
        FormsModule,
        AnalyticsRoutingModule
    ],
    declarations: [
        LayoutComponent,
        DashboardComponent,
        UsersOnlineComponent
    ]
})
export class AnalyticsModule { } 