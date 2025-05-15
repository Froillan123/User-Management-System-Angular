import { NgModule } from '@angular/core';
import { Routes, RouterModule } from '@angular/router';

import { ListComponent } from './list.component';
import { AddEditComponent } from './add-edit.component';
import { TransferComponent } from './transfer.component';
import { WorkflowsComponent } from './workflows.component';
import { RequestsComponent } from './requests.component';

const routes: Routes = [
    { path: '', component: ListComponent },
    { path: 'add', component: AddEditComponent },
    { path: 'edit/:id', component: AddEditComponent },
    { path: 'transfer/:id', component: TransferComponent },
    { path: 'workflows/:id', component: WorkflowsComponent },
    { path: 'requests/:id', component: RequestsComponent }
];

@NgModule({
    imports: [RouterModule.forChild(routes)],
    exports: [RouterModule]
})
export class EmployeesRoutingModule { } 