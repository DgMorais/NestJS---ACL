import { ApiProperty } from '@nestjs/swagger';
import { IsString, IsNotEmpty, IsEmail, MinLength } from 'class-validator';

export class CreateUserDto {
    @ApiProperty({ example: 'João Doe', description: 'Nome do usuário' })
    @IsString()
    @IsNotEmpty()
    readonly name: string;

    @ApiProperty({ example: 'joao_doe@example.com', description: 'Email do usuário' })
    @IsEmail()
    @IsNotEmpty()
    readonly email: string;

    @ApiProperty({ example: 'senha123', description: 'Senha do usuário' })
    @IsString()
    @MinLength(6)
    @IsNotEmpty()
    readonly password: string;
}
