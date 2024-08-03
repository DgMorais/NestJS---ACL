import { Module, forwardRef } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { GroupsService } from './groups.service';
import { GroupsController } from './groups.controller';
import { Group } from './entities/group.entity';
import { Role } from '../roles/entities/role.entity';
import { User } from '../users/entities/user.entity';
import { AuthModule } from '../auth/auth.module';

@Module({
    imports: [
        TypeOrmModule.forFeature([Group, Role, User]),
        forwardRef(() => AuthModule),
    ],
    controllers: [GroupsController],
    providers: [GroupsService],
    exports: [GroupsService],
})
export class GroupsModule { }
