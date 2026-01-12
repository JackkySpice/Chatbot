.class public abstract Landroidx/appcompat/view/menu/r1;
.super Ljava/lang/Object;
.source "SourceFile"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Landroidx/appcompat/view/menu/r1$a;,
        Landroidx/appcompat/view/menu/r1$e;,
        Landroidx/appcompat/view/menu/r1$b;,
        Landroidx/appcompat/view/menu/r1$d;,
        Landroidx/appcompat/view/menu/r1$c;
    }
.end annotation


# static fields
.field public static final a:Landroidx/appcompat/view/menu/co0;

.field public static b:Landroidx/appcompat/view/menu/co0$b;

.field public static c:Landroidx/appcompat/view/menu/co0$b;

.field public static d:Landroidx/appcompat/view/menu/co0$b;

.field public static e:Landroidx/appcompat/view/menu/co0$b;

.field public static f:Landroidx/appcompat/view/menu/co0$b;

.field public static g:Landroidx/appcompat/view/menu/co0$b;

.field public static h:Landroidx/appcompat/view/menu/co0$b;

.field public static i:Landroidx/appcompat/view/menu/co0$b;

.field public static j:Landroidx/appcompat/view/menu/co0$e;

.field public static k:Landroidx/appcompat/view/menu/co0$d;

.field public static l:Landroidx/appcompat/view/menu/co0$d;

.field public static m:Landroidx/appcompat/view/menu/co0$d;

.field public static n:Landroidx/appcompat/view/menu/co0$d;

.field public static o:Landroidx/appcompat/view/menu/co0$d;


# direct methods
.method static constructor <clinit>()V
    .locals 6

    const-string v0, "android.app.ActivityThread"

    invoke-static {v0}, Landroidx/appcompat/view/menu/co0;->w(Ljava/lang/String;)Landroidx/appcompat/view/menu/co0;

    move-result-object v0

    sput-object v0, Landroidx/appcompat/view/menu/r1;->a:Landroidx/appcompat/view/menu/co0;

    const-string v1, "sPackageManager"

    invoke-virtual {v0, v1}, Landroidx/appcompat/view/menu/co0;->e(Ljava/lang/String;)Landroidx/appcompat/view/menu/co0$b;

    move-result-object v1

    sput-object v1, Landroidx/appcompat/view/menu/r1;->b:Landroidx/appcompat/view/menu/co0$b;

    const-string v1, "sPermissionManager"

    invoke-virtual {v0, v1}, Landroidx/appcompat/view/menu/co0;->e(Ljava/lang/String;)Landroidx/appcompat/view/menu/co0$b;

    move-result-object v1

    sput-object v1, Landroidx/appcompat/view/menu/r1;->c:Landroidx/appcompat/view/menu/co0$b;

    const-string v1, "mActivities"

    invoke-virtual {v0, v1}, Landroidx/appcompat/view/menu/co0;->e(Ljava/lang/String;)Landroidx/appcompat/view/menu/co0$b;

    move-result-object v1

    sput-object v1, Landroidx/appcompat/view/menu/r1;->d:Landroidx/appcompat/view/menu/co0$b;

    const-string v1, "mBoundApplication"

    invoke-virtual {v0, v1}, Landroidx/appcompat/view/menu/co0;->e(Ljava/lang/String;)Landroidx/appcompat/view/menu/co0$b;

    move-result-object v1

    sput-object v1, Landroidx/appcompat/view/menu/r1;->e:Landroidx/appcompat/view/menu/co0$b;

    const-string v1, "mH"

    invoke-virtual {v0, v1}, Landroidx/appcompat/view/menu/co0;->e(Ljava/lang/String;)Landroidx/appcompat/view/menu/co0$b;

    move-result-object v1

    sput-object v1, Landroidx/appcompat/view/menu/r1;->f:Landroidx/appcompat/view/menu/co0$b;

    const-string v1, "mInitialApplication"

    invoke-virtual {v0, v1}, Landroidx/appcompat/view/menu/co0;->e(Ljava/lang/String;)Landroidx/appcompat/view/menu/co0$b;

    move-result-object v1

    sput-object v1, Landroidx/appcompat/view/menu/r1;->g:Landroidx/appcompat/view/menu/co0$b;

    const-string v1, "mInstrumentation"

    invoke-virtual {v0, v1}, Landroidx/appcompat/view/menu/co0;->e(Ljava/lang/String;)Landroidx/appcompat/view/menu/co0$b;

    move-result-object v1

    sput-object v1, Landroidx/appcompat/view/menu/r1;->h:Landroidx/appcompat/view/menu/co0$b;

    const-string v1, "mProviderMap"

    invoke-virtual {v0, v1}, Landroidx/appcompat/view/menu/co0;->e(Ljava/lang/String;)Landroidx/appcompat/view/menu/co0$b;

    move-result-object v1

    sput-object v1, Landroidx/appcompat/view/menu/r1;->i:Landroidx/appcompat/view/menu/co0$b;

    const/4 v1, 0x0

    new-array v2, v1, [Ljava/lang/Class;

    const-string v3, "currentActivityThread"

    invoke-virtual {v0, v3, v2}, Landroidx/appcompat/view/menu/co0;->z(Ljava/lang/String;[Ljava/lang/Class;)Landroidx/appcompat/view/menu/co0$e;

    move-result-object v2

    sput-object v2, Landroidx/appcompat/view/menu/r1;->j:Landroidx/appcompat/view/menu/co0$e;

    const-string v2, "getApplicationThread"

    new-array v3, v1, [Ljava/lang/Class;

    invoke-virtual {v0, v2, v3}, Landroidx/appcompat/view/menu/co0;->u(Ljava/lang/String;[Ljava/lang/Class;)Landroidx/appcompat/view/menu/co0$d;

    move-result-object v2

    sput-object v2, Landroidx/appcompat/view/menu/r1;->k:Landroidx/appcompat/view/menu/co0$d;

    const-string v2, "getSystemContext"

    new-array v3, v1, [Ljava/lang/Class;

    invoke-virtual {v0, v2, v3}, Landroidx/appcompat/view/menu/co0;->u(Ljava/lang/String;[Ljava/lang/Class;)Landroidx/appcompat/view/menu/co0$d;

    move-result-object v2

    sput-object v2, Landroidx/appcompat/view/menu/r1;->l:Landroidx/appcompat/view/menu/co0$d;

    const/4 v2, 0x1

    new-array v3, v2, [Ljava/lang/Class;

    const-class v4, Landroid/os/IBinder;

    aput-object v4, v3, v1

    const-string v5, "getLaunchingActivity"

    invoke-virtual {v0, v5, v3}, Landroidx/appcompat/view/menu/co0;->u(Ljava/lang/String;[Ljava/lang/Class;)Landroidx/appcompat/view/menu/co0$d;

    move-result-object v3

    sput-object v3, Landroidx/appcompat/view/menu/r1;->m:Landroidx/appcompat/view/menu/co0$d;

    const/4 v3, 0x2

    new-array v5, v3, [Ljava/lang/Class;

    aput-object v4, v5, v1

    const-class v4, Ljava/util/List;

    aput-object v4, v5, v2

    const-string v4, "performNewIntents"

    invoke-virtual {v0, v4, v5}, Landroidx/appcompat/view/menu/co0;->u(Ljava/lang/String;[Ljava/lang/Class;)Landroidx/appcompat/view/menu/co0$d;

    move-result-object v4

    sput-object v4, Landroidx/appcompat/view/menu/r1;->n:Landroidx/appcompat/view/menu/co0$d;

    const/4 v4, 0x6

    new-array v4, v4, [Ljava/lang/Class;

    const-class v5, Landroid/content/Context;

    aput-object v5, v4, v1

    const-string v1, "android.app.ContentProviderHolder"

    invoke-static {v1}, Landroidx/appcompat/view/menu/co0;->v(Ljava/lang/String;)Ljava/lang/Class;

    move-result-object v1

    aput-object v1, v4, v2

    const-class v1, Landroid/content/pm/ProviderInfo;

    aput-object v1, v4, v3

    sget-object v1, Ljava/lang/Boolean;->TYPE:Ljava/lang/Class;

    const/4 v2, 0x3

    aput-object v1, v4, v2

    const/4 v2, 0x4

    aput-object v1, v4, v2

    const/4 v2, 0x5

    aput-object v1, v4, v2

    const-string v1, "installProvider"

    invoke-virtual {v0, v1, v4}, Landroidx/appcompat/view/menu/co0;->u(Ljava/lang/String;[Ljava/lang/Class;)Landroidx/appcompat/view/menu/co0$d;

    move-result-object v0

    sput-object v0, Landroidx/appcompat/view/menu/r1;->o:Landroidx/appcompat/view/menu/co0$d;

    return-void
.end method
