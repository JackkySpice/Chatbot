.class public abstract Landroidx/appcompat/view/menu/z4;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static final a:Landroidx/appcompat/view/menu/co0;

.field public static b:Landroidx/appcompat/view/menu/co0$a;

.field public static c:Landroidx/appcompat/view/menu/co0$d;


# direct methods
.method static constructor <clinit>()V
    .locals 4

    const-string v0, "android.content.res.AssetManager"

    invoke-static {v0}, Landroidx/appcompat/view/menu/co0;->w(Ljava/lang/String;)Landroidx/appcompat/view/menu/co0;

    move-result-object v0

    sput-object v0, Landroidx/appcompat/view/menu/z4;->a:Landroidx/appcompat/view/menu/co0;

    const/4 v1, 0x0

    new-array v2, v1, [Ljava/lang/Class;

    invoke-virtual {v0, v2}, Landroidx/appcompat/view/menu/co0;->c([Ljava/lang/Class;)Landroidx/appcompat/view/menu/co0$a;

    move-result-object v2

    sput-object v2, Landroidx/appcompat/view/menu/z4;->b:Landroidx/appcompat/view/menu/co0$a;

    const/4 v2, 0x1

    new-array v2, v2, [Ljava/lang/Class;

    const-class v3, Ljava/lang/String;

    aput-object v3, v2, v1

    const-string v1, "addAssetPath"

    invoke-virtual {v0, v1, v2}, Landroidx/appcompat/view/menu/co0;->u(Ljava/lang/String;[Ljava/lang/Class;)Landroidx/appcompat/view/menu/co0$d;

    move-result-object v0

    sput-object v0, Landroidx/appcompat/view/menu/z4;->c:Landroidx/appcompat/view/menu/co0$d;

    return-void
.end method
