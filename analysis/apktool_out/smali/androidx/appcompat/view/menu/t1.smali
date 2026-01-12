.class public abstract Landroidx/appcompat/view/menu/t1;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static final a:Landroidx/appcompat/view/menu/co0;

.field public static b:Landroidx/appcompat/view/menu/co0$d;


# direct methods
.method static constructor <clinit>()V
    .locals 4

    const-string v0, "android.app.ActivityThread"

    invoke-static {v0}, Landroidx/appcompat/view/menu/co0;->w(Ljava/lang/String;)Landroidx/appcompat/view/menu/co0;

    move-result-object v0

    sput-object v0, Landroidx/appcompat/view/menu/t1;->a:Landroidx/appcompat/view/menu/co0;

    const/4 v1, 0x2

    new-array v1, v1, [Ljava/lang/Class;

    const/4 v2, 0x0

    const-class v3, Landroid/os/IBinder;

    aput-object v3, v1, v2

    const/4 v2, 0x1

    const-class v3, Ljava/util/List;

    aput-object v3, v1, v2

    const-string v2, "handleNewIntent"

    invoke-virtual {v0, v2, v1}, Landroidx/appcompat/view/menu/co0;->u(Ljava/lang/String;[Ljava/lang/Class;)Landroidx/appcompat/view/menu/co0$d;

    move-result-object v0

    sput-object v0, Landroidx/appcompat/view/menu/t1;->b:Landroidx/appcompat/view/menu/co0$d;

    return-void
.end method
