.class public abstract Landroidx/appcompat/view/menu/cl1;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static final a:Landroidx/appcompat/view/menu/el1;

.field public static volatile b:Landroidx/appcompat/view/menu/el1;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    new-instance v0, Landroidx/appcompat/view/menu/il1;

    const/4 v1, 0x0

    invoke-direct {v0, v1}, Landroidx/appcompat/view/menu/il1;-><init>(Landroidx/appcompat/view/menu/gl1;)V

    sput-object v0, Landroidx/appcompat/view/menu/cl1;->a:Landroidx/appcompat/view/menu/el1;

    sput-object v0, Landroidx/appcompat/view/menu/cl1;->b:Landroidx/appcompat/view/menu/el1;

    return-void
.end method

.method public static a()Landroidx/appcompat/view/menu/el1;
    .locals 1

    sget-object v0, Landroidx/appcompat/view/menu/cl1;->b:Landroidx/appcompat/view/menu/el1;

    return-object v0
.end method
