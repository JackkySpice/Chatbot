.class public final Landroidx/appcompat/view/menu/lp;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Landroidx/appcompat/view/menu/uq;


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Landroidx/appcompat/view/menu/lp$a;
    }
.end annotation


# direct methods
.method public constructor <init>()V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public static a()Landroidx/appcompat/view/menu/lp;
    .locals 1

    invoke-static {}, Landroidx/appcompat/view/menu/lp$a;->a()Landroidx/appcompat/view/menu/lp;

    move-result-object v0

    return-object v0
.end method

.method public static c()Landroidx/appcompat/view/menu/gp;
    .locals 2

    invoke-static {}, Landroidx/appcompat/view/menu/hp;->d()Landroidx/appcompat/view/menu/gp;

    move-result-object v0

    const-string v1, "Cannot return null from a non-@Nullable @Provides method"

    invoke-static {v0, v1}, Landroidx/appcompat/view/menu/hj0;->c(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Landroidx/appcompat/view/menu/gp;

    return-object v0
.end method


# virtual methods
.method public b()Landroidx/appcompat/view/menu/gp;
    .locals 1

    invoke-static {}, Landroidx/appcompat/view/menu/lp;->c()Landroidx/appcompat/view/menu/gp;

    move-result-object v0

    return-object v0
.end method

.method public bridge synthetic get()Ljava/lang/Object;
    .locals 1

    invoke-virtual {p0}, Landroidx/appcompat/view/menu/lp;->b()Landroidx/appcompat/view/menu/gp;

    move-result-object v0

    return-object v0
.end method
