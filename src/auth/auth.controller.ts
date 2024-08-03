import { Controller, Request, Post, UseGuards, Body, Logger } from '@nestjs/common';
import { AuthService } from './auth.service';
import { LocalAuthGuard } from './guards/local-auth.guard';
import { JwtAuthGuard } from './guards/jwt-auth.guard';
import { RegisterDto } from './dto/register.dto';
import { LoginDto } from './dto/login.dto';
import { ApiTags, ApiOperation, ApiResponse } from '@nestjs/swagger';

@ApiTags('auth')
@Controller('auth')
export class AuthController {
    private readonly logger = new Logger(AuthController.name);

    constructor(private readonly authService: AuthService) { }

    @UseGuards(LocalAuthGuard)
    @Post('login')
    @ApiOperation({ summary: 'Login do usuário' })
    @ApiResponse({ status: 200, description: 'Login bem-sucedido' })
    @ApiResponse({ status: 401, description: 'Credenciais inválidas' })
    async login(@Body() loginDto: LoginDto, @Request() req: any) {
        return this.authService.login(req.user);
    }

    @Post('register')
    @ApiOperation({ summary: 'Registro de novo usuário' })
    @ApiResponse({ status: 201, description: 'Usuário registrado com sucesso' })
    @ApiResponse({ status: 400, description: 'Dados inválidos' })
    async register(@Body() registerDto: RegisterDto) {
        return this.authService.register(registerDto);
    }

    @UseGuards(JwtAuthGuard)
    @Post('profile')
    @ApiOperation({ summary: 'Perfil do usuário' })
    @ApiResponse({ status: 200, description: 'Perfil do usuário retornado com sucesso' })
    @ApiResponse({ status: 401, description: 'Usuário não autorizado' })
    getProfile(@Request() req: any) {
        return req.user;
    }

    @Post('refresh')
    @ApiOperation({ summary: 'Atualização do token' })
    @ApiResponse({ status: 200, description: 'Token atualizado com sucesso' })
    @ApiResponse({ status: 400, description: 'Refresh token inválido' })
    async refresh(@Body('refresh_token') refreshToken: string) {
        return this.authService.refreshToken(refreshToken);
    }
}
