import { Entity, PrimaryGeneratedColumn, Column, ManyToMany, JoinTable } from 'typeorm';
import { Role } from '../../roles/entities/role.entity';
import { User } from '../../users/entities/user.entity';
import { ApiProperty } from '@nestjs/swagger';

@Entity('groups') // Certifique-se de que o nome da tabela é "groups"
export class Group {
    @ApiProperty({ example: 1, description: 'ID do grupo' })
    @PrimaryGeneratedColumn()
    id: number;

    @ApiProperty({ example: 'Admin', description: 'Nome do grupo' })
    @Column()
    name: string;

    @ApiProperty({ type: () => [Role], description: 'Roles associados ao grupo' })
    @ManyToMany(() => Role, (role) => role.groups, { cascade: true })
    @JoinTable()
    roles: Role[];

    @ApiProperty({ type: () => [User], description: 'Usuários associados ao grupo' })
    @ManyToMany(() => User, (user) => user.groups)
    users: User[];
}
