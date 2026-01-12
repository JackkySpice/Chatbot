.class public final synthetic Landroidx/appcompat/view/menu/pe;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Ljava/lang/Runnable;


# instance fields
.field public final synthetic m:Landroidx/appcompat/view/menu/l80;

.field public final synthetic n:Landroidx/appcompat/view/menu/al0;


# direct methods
.method public synthetic constructor <init>(Landroidx/appcompat/view/menu/l80;Landroidx/appcompat/view/menu/al0;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Landroidx/appcompat/view/menu/pe;->m:Landroidx/appcompat/view/menu/l80;

    iput-object p2, p0, Landroidx/appcompat/view/menu/pe;->n:Landroidx/appcompat/view/menu/al0;

    return-void
.end method


# virtual methods
.method public final run()V
    .locals 2

    iget-object v0, p0, Landroidx/appcompat/view/menu/pe;->m:Landroidx/appcompat/view/menu/l80;

    iget-object v1, p0, Landroidx/appcompat/view/menu/pe;->n:Landroidx/appcompat/view/menu/al0;

    invoke-static {v0, v1}, Landroidx/appcompat/view/menu/qe;->i(Landroidx/appcompat/view/menu/l80;Landroidx/appcompat/view/menu/al0;)V

    return-void
.end method
