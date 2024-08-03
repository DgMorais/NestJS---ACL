import { Strategy } from 'passport-local';
import { PassportStrategy } from '@nestjs/passport';
import { Injectable, Logger, UnauthorizedException } from '@nestjs/common';
import { AuthService } from '../auth.service';

@Injectable()
export class LocalStrategy extends PassportStrategy(Strategy) {
    private readonly logger = new Logger(LocalStrategy.name);

    constructor(private authService: AuthService) {
        super({
            usernameField: 'email',
            passwordField: 'password',
        });
    }

    async validate(email: string, password: string): Promise<any> {
        const trimmedEmail = email.trim();
        const trimmedPassword = password.trim();

        const user = await this.authService.validateUser(trimmedEmail, trimmedPassword);
        if (!user) {
            this.logger.error('Invalid credentials');
            throw new UnauthorizedException();
        }
        return user;
    }
}
