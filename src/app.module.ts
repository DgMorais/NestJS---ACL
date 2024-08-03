import { Module, OnModuleInit, Logger, NotFoundException } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { UsersModule } from './users/users.module';
import { AuthModule } from './auth/auth.module';
import { RolesModule } from './roles/roles.module';
import { PermissionsModule } from './permissions/permissions.module';
import { GroupsModule } from './groups/groups.module';
import { User } from './users/entities/user.entity';
import { Role } from './roles/entities/role.entity';
import { Permission } from './permissions/entities/permission.entity';
import { Group } from './groups/entities/group.entity';
import AppDataSource from '../config/ormconfig';
import { GroupsService } from './groups/groups.service';

@Module({
    imports: [
        ConfigModule.forRoot({
            isGlobal: true,
            envFilePath: './config/.env',
        }),
        TypeOrmModule.forRoot(AppDataSource.options),
        TypeOrmModule.forFeature([User, Role, Permission, Group]),
        UsersModule,
        AuthModule,
        RolesModule,
        PermissionsModule,
        GroupsModule,
    ],
    providers: [GroupsService],
})
export class AppModule implements OnModuleInit {
    private readonly logger = new Logger(AppModule.name);

    constructor(private readonly groupsService: GroupsService) {}

    async onModuleInit() {
        try {
            this.logger.debug('Verificando se o grupo "admins" existe...');
            const adminGroup = await this.groupsService.findByName('admins');
            this.logger.debug(`Grupo "admins" encontrado: ${JSON.stringify(adminGroup)}`);
        } catch (error) {
            if (error instanceof NotFoundException) {
                this.logger.debug('Grupo "admins" não encontrado, criando grupo...');
                const newGroup = await this.groupsService.create({ name: 'admins', roleIds: [] });
                this.logger.debug(`Grupo "admins" criado: ${JSON.stringify(newGroup)}`);
            } else {
                this.logger.error('Erro ao verificar/criar o grupo "admins":', error);
            }
        }
    }
}
