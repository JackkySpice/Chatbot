.class public final Landroidx/appcompat/view/menu/ku1;
.super Landroid/database/ContentObserver;
.source "SourceFile"


# instance fields
.field public final synthetic a:Landroidx/appcompat/view/menu/zt1;


# direct methods
.method public constructor <init>(Landroidx/appcompat/view/menu/zt1;Landroid/os/Handler;)V
    .locals 0

    iput-object p1, p0, Landroidx/appcompat/view/menu/ku1;->a:Landroidx/appcompat/view/menu/zt1;

    const/4 p1, 0x0

    invoke-direct {p0, p1}, Landroid/database/ContentObserver;-><init>(Landroid/os/Handler;)V

    return-void
.end method


# virtual methods
.method public final onChange(Z)V
    .locals 0

    iget-object p1, p0, Landroidx/appcompat/view/menu/ku1;->a:Landroidx/appcompat/view/menu/zt1;

    invoke-virtual {p1}, Landroidx/appcompat/view/menu/zt1;->e()V

    return-void
.end method
