import { NgModule } from '@angular/core';
import { ReactiveFormsModule } from '@angular/forms';
import { CommonModule } from '@angular/common';

import { EmployeesRoutingModule } from './employees-routing.module';
import { ListComponent } from './list.component';
import { AddEditComponent } from './add-edit.component';
import { TransferComponent } from './transfer.component';
import { WorkflowsComponent } from './workflows.component';
import { RequestsComponent } from './requests.component';

@NgModule({
    imports: [
        CommonModule,
        ReactiveFormsModule,
        EmployeesRoutingModule
    ],
    declarations: [
        ListComponent,
        AddEditComponent,
        TransferComponent,
        WorkflowsComponent,
        RequestsComponent
    ]
})
export class EmployeesModule { } 