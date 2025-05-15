import { Role } from './role';

export interface Account {
  id: string;
  title: string;
  firstName: string;
  lastName: string;
  email: string;
  role: string;
  jwtToken?: string;
  refreshToken?: string;
  isVerified: boolean;
  acceptTerms: boolean;
  lastActive?: Date;
  isOnline?: boolean;
  status?: string;
}
