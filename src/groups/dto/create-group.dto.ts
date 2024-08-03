import { ApiProperty } from '@nestjs/swagger';
import { IsString, IsNotEmpty, IsArray, IsNumber } from 'class-validator';

export class CreateGroupDto {
    @ApiProperty({ example: 'Admin', description: 'O nome do grupo' })
    @IsString()
    @IsNotEmpty()
    readonly name: string;

    @ApiProperty({ example: [1, 2], description: 'IDs dos roles associados ao grupo' })
    @IsArray()
    @IsNumber({}, { each: true }) // Adiciona validação para garantir que cada item no array é um número
    readonly roleIds: number[];
}
