import { ApiProperty } from '@nestjs/swagger';
import { IsString, IsNotEmpty } from 'class-validator';

export class CreatePermissionDto {
    @ApiProperty({ example: 'create_user', description: 'O nome da permissão' })
    @IsString()
    @IsNotEmpty()
    readonly name: string;

    @ApiProperty({ example: 'Permite criar um usuário', description: 'A descrição da permissão' })
    @IsString()
    @IsNotEmpty()
    readonly description: string;
}
