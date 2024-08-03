import { Entity, PrimaryGeneratedColumn, Column, ManyToMany } from 'typeorm';
import { ApiProperty } from '@nestjs/swagger';
import { Permission } from '../../permissions/entities/permission.entity';
import { User } from '../../users/entities/user.entity';
import { Group } from '../../groups/entities/group.entity';

@Entity('roles')
export class Role {
    @ApiProperty({ example: 1, description: 'ID do role' })
    @PrimaryGeneratedColumn()
    id: number;

    @ApiProperty({ example: 'Admin', description: 'Nome do role' })
    @Column()
    name: string;

    @ApiProperty({ type: () => [Permission], description: 'Permissões associadas ao role' })
    @ManyToMany(() => Permission, (permission) => permission.roles, { cascade: true })
    permissions: Permission[];

    @ApiProperty({ type: () => [User], description: 'Usuários associados ao role' })
    @ManyToMany(() => User, (user) => user.roles)
    users: User[];

    @ApiProperty({ type: () => [Group], description: 'Grupos associados ao role' })
    @ManyToMany(() => Group, (group) => group.roles)
    groups: Group[];
}
