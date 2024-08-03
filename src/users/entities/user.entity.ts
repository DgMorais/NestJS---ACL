import { Entity, PrimaryGeneratedColumn, Column, ManyToMany } from 'typeorm';
import { ApiProperty } from '@nestjs/swagger';
import { Role } from '../../roles/entities/role.entity';
import { Group } from '../../groups/entities/group.entity';

@Entity('users')
export class User {
    @ApiProperty({ example: 1, description: 'ID do usuário' })
    @PrimaryGeneratedColumn()
    id: number;

    @ApiProperty({ example: 'João Doe', description: 'Nome do usuário' })
    @Column({ length: 100 })
    name: string;

    @ApiProperty({ example: 'joao_doe@example.com', description: 'Email do usuário' })
    @Column({ unique: true, length: 100 })
    email: string;

    @ApiProperty({ example: 'senha123', description: 'Senha do usuário' })
    @Column('text')
    password: string;

    @ApiProperty({ type: () => [Role], description: 'Roles associados ao usuário' })
    @ManyToMany(() => Role, (role) => role.users, { cascade: true })
    roles: Role[];

    @ApiProperty({ type: () => [Group], description: 'Grupos associados ao usuário' })
    @ManyToMany(() => Group, (group) => group.users)
    groups: Group[];
}
