import { ApiProperty } from '@nestjs/swagger';
import { IsString, IsNotEmpty, IsArray, IsNumber } from 'class-validator';

export class CreateRoleDto {
    @ApiProperty({ example: 'Admin', description: 'O nome do role' })
    @IsString()
    @IsNotEmpty()
    readonly name: string;

    @ApiProperty({ example: [1, 2], description: 'IDs das permissões associadas ao role' })
    @IsArray()
    @IsNumber({}, { each: true }) // Adiciona validação para garantir que cada item no array é um número
    readonly permissionIds: number[];
}
