import { Module, forwardRef } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { RolesService } from './roles.service';
import { RolesController } from './roles.controller';
import { Role } from './entities/role.entity';
import { Permission } from '../permissions/entities/permission.entity';
import { AuthModule } from '../auth/auth.module'; // Importar AuthModule

@Module({
    imports: [
        TypeOrmModule.forFeature([Role, Permission]),
        forwardRef(() => AuthModule), // Adicionar AuthModule
    ],
    controllers: [RolesController],
    providers: [RolesService],
})
export class RolesModule { }
