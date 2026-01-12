.class public abstract Landroidx/appcompat/view/menu/vo1;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static final a:Landroidx/appcompat/view/menu/fh1;

.field public static volatile b:Landroidx/appcompat/view/menu/fh1;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    new-instance v0, Landroidx/appcompat/view/menu/tm1;

    const/4 v1, 0x0

    invoke-direct {v0, v1}, Landroidx/appcompat/view/menu/tm1;-><init>(Landroidx/appcompat/view/menu/jk1;)V

    sput-object v0, Landroidx/appcompat/view/menu/vo1;->a:Landroidx/appcompat/view/menu/fh1;

    sput-object v0, Landroidx/appcompat/view/menu/vo1;->b:Landroidx/appcompat/view/menu/fh1;

    return-void
.end method

.method public static a()Landroidx/appcompat/view/menu/fh1;
    .locals 1

    sget-object v0, Landroidx/appcompat/view/menu/vo1;->b:Landroidx/appcompat/view/menu/fh1;

    return-object v0
.end method
