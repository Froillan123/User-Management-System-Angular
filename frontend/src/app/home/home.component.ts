import { Component, OnInit } from '@angular/core';

import { AccountService } from '../../app/_services';
import { Role } from '../../app/_models';

@Component({
    templateUrl: 'home.component.html',
    styles: [`
        .welcome-banner {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            border-radius: 12px;
            overflow: hidden;
            position: relative;
            box-shadow: 0 10px 20px rgba(0,0,0,0.1);
        }
        
        .welcome-text {
            color: white;
            text-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        
        .welcome-shape {
            position: absolute;
            bottom: -30px;
            right: -30px;
            width: 200px;
            height: 200px;
            border-radius: 50%;
            background: rgba(255,255,255,0.1);
            z-index: 0;
        }
        
        .welcome-shape-2 {
            position: absolute;
            top: -30px;
            left: -30px;
            width: 120px;
            height: 120px;
            border-radius: 50%;
            background: rgba(255,255,255,0.1);
            z-index: 0;
        }
        
        .feature-card {
            border-radius: 12px;
            transition: all 0.3s ease;
            border: none;
            box-shadow: 0 4px 12px rgba(0,0,0,0.05);
        }
        
        .feature-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 8px 16px rgba(0,0,0,0.1);
        }
        
        .card-title-icon {
            width: 48px;
            height: 48px;
            display: flex;
            align-items: center;
            justify-content: center;
            border-radius: 12px;
            margin-bottom: 15px;
        }
        
        .user-avatar {
            width: 100px;
            height: 100px;
            border-radius: 50%;
            background-color: #e0e7ff;
            display: flex;
            align-items: center;
            justify-content: center;
            margin: 0 auto 20px;
            box-shadow: 0 4px 10px rgba(0,0,0,0.1);
        }
        
        .dashboard-card {
            border-radius: 12px;
            height: 100%;
            transition: all 0.3s ease;
            border: none;
            box-shadow: 0 4px 12px rgba(0,0,0,0.05);
        }
        
        .dashboard-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 8px 16px rgba(0,0,0,0.1);
        }
    `]
})
export class HomeComponent implements OnInit {
    account: any;
    Role = Role;

    constructor(private accountService: AccountService) {}
    
    ngOnInit() {
        this.accountService.account.subscribe(x => {
            this.account = x;
        });
    }
}