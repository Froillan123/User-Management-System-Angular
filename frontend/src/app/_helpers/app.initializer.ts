import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { firstValueFrom } from 'rxjs';

import { environment } from '../../environments/environment';
import { AccountService } from '../../app/_services';

@Injectable({ providedIn: 'root' })
export class AppInitializer {
  constructor(private accountService: AccountService) { }

  initialize() {
    return new Promise<void>((resolve) => {
      const account = this.accountService.accountValue;
      if (account?.jwtToken) {
        this.accountService.refreshToken().subscribe({
          next: () => resolve(),
          error: () => {
            this.accountService.logout();
            resolve();
          }
        });
      } else {
        resolve();
      }
    });
  }
}

export function appInitializer(accountService: AccountService) {
  const initializer = new AppInitializer(accountService);
  return () => initializer.initialize();
}
