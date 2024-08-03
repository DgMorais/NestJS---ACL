import { Entity, PrimaryGeneratedColumn, Column, ManyToMany } from 'typeorm';
import { Role } from '../../roles/entities/role.entity';
import { ApiProperty } from '@nestjs/swagger';

@Entity('permissions')
export class Permission {
    @ApiProperty({ example: 1, description: 'ID da permissão' })
    @PrimaryGeneratedColumn()
    id: number;

    @ApiProperty({ example: 'create_user', description: 'Nome da permissão' })
    @Column()
    name: string;

    @ApiProperty({ example: 'Permite criar um usuário', description: 'Descrição da permissão' })
    @Column()
    description: string;

    @ApiProperty({ type: () => [Role], description: 'Roles associados à permissão' })
    @ManyToMany(() => Role, (role) => role.permissions)
    roles: Role[];
}
