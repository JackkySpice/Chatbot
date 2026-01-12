.class public abstract Landroidx/appcompat/view/menu/vo;
.super Ljava/lang/Object;
.source "SourceFile"


# direct methods
.method public constructor <init>()V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public static e(Ljava/lang/Object;Landroidx/appcompat/view/menu/dk0;)Landroidx/appcompat/view/menu/vo;
    .locals 3

    new-instance v0, Landroidx/appcompat/view/menu/r5;

    const/4 v1, 0x0

    sget-object v2, Landroidx/appcompat/view/menu/pj0;->m:Landroidx/appcompat/view/menu/pj0;

    invoke-direct {v0, v1, p0, v2, p1}, Landroidx/appcompat/view/menu/r5;-><init>(Ljava/lang/Integer;Ljava/lang/Object;Landroidx/appcompat/view/menu/pj0;Landroidx/appcompat/view/menu/dk0;)V

    return-object v0
.end method


# virtual methods
.method public abstract a()Ljava/lang/Integer;
.end method

.method public abstract b()Ljava/lang/Object;
.end method

.method public abstract c()Landroidx/appcompat/view/menu/pj0;
.end method

.method public abstract d()Landroidx/appcompat/view/menu/dk0;
.end method
