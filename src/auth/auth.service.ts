import { Inject, Injectable, Logger, NotFoundException, forwardRef } from '@nestjs/common';
import { UsersService } from '../users/users.service';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcrypt';
import { RegisterDto } from './dto/register.dto';
import { ConfigService } from '@nestjs/config';
import { GroupsService } from 'src/groups/groups.service';

@Injectable()
export class AuthService {
    private readonly logger = new Logger(AuthService.name);

    constructor(
        @Inject(forwardRef(() => UsersService))
        private usersService: UsersService,
        private jwtService: JwtService,
        private readonly configService: ConfigService,
        private readonly groupsService: GroupsService,
    ) { }

    async validateUser(email: string, password: string): Promise<any> {
        try {
            const user = await this.usersService.findOneByEmailWithPassword(email);

            const passwordMatches = await bcrypt.compare(password, user.password);

            if (user && passwordMatches) {
                const { password, ...result } = user;
                return result;
            }
        } catch (error) {
            this.logger.error(`Error validating user: ${error.message}`);
        }
        this.logger.debug(`Invalid credentials for email: ${email}`);
        return null;
    }

    async login(user: any) {
        const payload = { email: user.email, sub: user.id };

        return {
            access_token: this.jwtService.sign(payload),
            refresh_token: this.jwtService.sign(payload, {
                secret: this.configService.get<string>('JWT_REFRESH_SECRET'),
                expiresIn: '7d',
            }),
        };
    }

    async register(registerDto: RegisterDto) {
        const salt = await bcrypt.genSalt(10);

        const hashedPassword = await bcrypt.hash(registerDto.password, 10);
        this.logger.debug(`${hashedPassword}`);
        const user = await this.usersService.create({
            ...registerDto,
            password: hashedPassword,
        });

        try {
            const userGroup = await this.groupsService.findByName('users');
            user.groups = [userGroup];
            await this.usersService.update(user.id, user);
        } catch (error) {
            if (error instanceof NotFoundException) {
                this.logger.warn('Grupo "users" não encontrado. Usuário registrado sem grupo associado.');
            } else {
                throw error;
            }
        }

        return user;
    }

    async refreshToken(refreshToken: string) {
        try {
            const payload = this.jwtService.verify(refreshToken, {
                secret: this.configService.get<string>('JWT_REFRESH_SECRET'),
            });
            const user = await this.usersService.findOne(payload.sub);
            if (!user) {
                throw new Error('User not found');
            }
            return this.login(user);
        } catch (e) {
            throw new Error('Invalid refresh token');
        }
    }
}
