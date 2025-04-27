import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { firstValueFrom } from 'rxjs';

import { environment } from '../../environments/environment';
import { AccountService } from '../_services';

@Injectable({ providedIn: 'root' })
export class AppInitializer {
  constructor(private accountService: AccountService) { }

  initialize() {
    return new Promise<void>((resolve) => {
      // Check if there's an account in local storage
      const account = this.accountService.accountValue;
      
      if (account?.jwtToken) {
        // Attempt to refresh the token
        this.accountService.refreshToken().subscribe({
          next: () => {
            console.log('Token refreshed successfully during app initialization');
            resolve();
          },
          error: (error) => {
            console.error('Token refresh failed during app initialization:', error);
            // If token refresh fails, logout and redirect to login page
            this.accountService.logout();
            resolve();
          }
        });
      } else {
        // No stored account, just resolve
        resolve();
      }
    });
  }
}

export function appInitializer(accountService: AccountService) {
  const initializer = new AppInitializer(accountService);
  return () => initializer.initialize();
}
