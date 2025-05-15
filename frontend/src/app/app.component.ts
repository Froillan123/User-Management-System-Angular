import { Component, OnInit } from '@angular/core';
import { AccountService } from './_services';
import { Account, Role } from './_models';

@Component({
  selector: 'app',
  templateUrl: 'app.component.html',
  styleUrls: ['app.component.css']
})
export class AppComponent implements OnInit {
  Role = Role;
  account: Account | null;

  constructor(private accountService: AccountService) {
    this.accountService.account.subscribe(x => this.account = x);
  }

  ngOnInit() {
    // Verify authentication on app startup/refresh
    this.accountService.verifyAuth();
  }

  logout() {
    this.accountService.logout();
  }
}